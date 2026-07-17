/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: public server foundation.
 * Invariants: versioned public configuration is validated before allocation,
 * string ownership is copied into the server object, and free is idempotent.
 * Ownership: the caller owns the input config; librdp_server owns copied
 * fields after successful creation.
 * Threading: no internal synchronization; callers serialize access to each
 * server object.
 * Trust boundary: server configuration is local application input and is
 * bounded before listener runtime consumes it.
 */

#include "server/server_internal.h"

#include "common/buffer.h"
#include "common/stream.h"
#include "common/trace.h"
#include "channels/audio_input.h"
#include "channels/audio_output.h"
#include "channels/auth_redirection.h"
#include "channels/composited_remoting.h"
#include "channels/core_input.h"
#include "channels/desktop_composition.h"
#include "channels/device_redirection.h"
#include "channels/display_control.h"
#include "channels/dynamic_channel.h"
#include "channels/echo_channel.h"
#include "channels/graphics_pipeline.h"
#include "channels/input_channel.h"
#include "channels/mouse_cursor.h"
#include "channels/multiparty.h"
#include "channels/remote_programs.h"
#include "channels/telemetry.h"
#include "channels/usb_redirection.h"
#include "channels/video_capture.h"
#include "channels/video_optimized.h"
#include "channels/video_redirection.h"
#include "channels/webauthn_channel.h"
#include "clipboard/clipboard.h"
#include "graphics/bitmap.h"
#include "graphics/gdi_orders.h"
#include "licensing/licensing.h"
#include "nla/credssp.h"
#include "platform/socket.h"
#include "protocol/gcc.h"
#include "protocol/mcs.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"
#include "transport/udp_transport.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define RDP_SERVER_DEFAULT_BACKLOG 4u
#define RDP_SERVER_DEFAULT_MAX_PEERS 16u
#define RDP_SERVER_DEFAULT_WIDTH 1024u
#define RDP_SERVER_DEFAULT_HEIGHT 768u
#define RDP_SERVER_MAX_TEXT 512u
#define RDP_SERVER_MAX_BACKLOG 128u
#define RDP_SERVER_MAX_PEERS 1024u
#define RDP_SERVER_MAX_DESKTOP_SIZE 8192u
#define RDP_SERVER_NEGOTIATION_FAILURE_SSL_REQUIRED 0x00000001u
#define RDP_SERVER_NEGOTIATION_FAILURE_SSL_NOT_ALLOWED 0x00000002u
#define RDP_SERVER_NEGOTIATION_FAILURE_SSL_CERT_NOT_ON_SERVER 0x00000003u
#define RDP_SERVER_NEGOTIATION_FAILURE_HYBRID_REQUIRED 0x00000005u
#define RDP_SERVER_INITIAL_READ_MAX 65535u
#define RDP_SERVER_CREDSSP_MESSAGE_MAX 1048576u
#define RDP_SERVER_STANDARD_ENCRYPTION_LEVEL 3u
#define RDP_SERVER_DYNAMIC_MESSAGE_MAX (64u * 1024u * 1024u)
#define RDP_SERVER_CLIPBOARD_CHANNEL_NAME "cliprdr"
#define RDP_SERVER_KNOWN_FEATURES                                                                                   \
    ((uint32_t)LIBRDP_FEATURE_AUDIO_OUTPUT | (uint32_t)LIBRDP_FEATURE_AUDIO_INPUT |                                  \
     (uint32_t)LIBRDP_FEATURE_VIDEO | (uint32_t)LIBRDP_FEATURE_CAMERA |                                              \
     (uint32_t)LIBRDP_FEATURE_SMARTCARD | (uint32_t)LIBRDP_FEATURE_USB |                                             \
     (uint32_t)LIBRDP_FEATURE_PNP | (uint32_t)LIBRDP_FEATURE_WEBAUTHN |                                              \
     (uint32_t)LIBRDP_FEATURE_RAIL | (uint32_t)LIBRDP_FEATURE_CR2 |                                                  \
     (uint32_t)LIBRDP_FEATURE_ECHO | (uint32_t)LIBRDP_FEATURE_TELEMETRY |                                            \
     (uint32_t)LIBRDP_FEATURE_MULTITRANSPORT | (uint32_t)LIBRDP_FEATURE_DESKTOP_COMPOSITION |                        \
     (uint32_t)LIBRDP_FEATURE_DISPLAY_CONTROL | (uint32_t)LIBRDP_FEATURE_UDP_TRANSPORT |                             \
     (uint32_t)LIBRDP_FEATURE_UDP2_TRANSPORT | (uint32_t)LIBRDP_FEATURE_GEOMETRY_TRACKING |                          \
     (uint32_t)LIBRDP_FEATURE_MULTIPARTY)

static void rdp_server_metric_add(uint64_t* metric, uint64_t value)
{
    if (!metric)
        return;
    if (UINT64_MAX - *metric < value)
        *metric = UINT64_MAX;
    else
        *metric += value;
}

static int rdp_server_valid_feature_mask(librdp_feature feature)
{
    uint32_t value = (uint32_t)feature;

    return value != 0 && (value & ~RDP_SERVER_KNOWN_FEATURES) == 0;
}

static int rdp_server_valid_single_feature(librdp_feature feature)
{
    uint32_t value = (uint32_t)feature;

    return rdp_server_valid_feature_mask(feature) && (value & (value - 1u)) == 0;
}

static void rdp_server_dynamic_channels_reset(librdp_server_peer* peer)
{
    if (!peer)
        return;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_DYNAMIC_CHANNELS; i++)
        rdp_buffer_free(&peer->dynamic_channels[i].fragment);
    memset(peer->dynamic_channels, 0, sizeof(peer->dynamic_channels));
    peer->dynamic_channel_count = 0;
    peer->dynamic_channel_static_index = UINT16_MAX;
    peer->dynamic_channels_ready = 0;
}

static int rdp_server_feature_has_runtime(librdp_feature feature)
{
    switch (feature)
    {
        case LIBRDP_FEATURE_AUDIO_OUTPUT:
        case LIBRDP_FEATURE_AUDIO_INPUT:
        case LIBRDP_FEATURE_VIDEO:
        case LIBRDP_FEATURE_CAMERA:
        case LIBRDP_FEATURE_SMARTCARD:
        case LIBRDP_FEATURE_USB:
        case LIBRDP_FEATURE_PNP:
        case LIBRDP_FEATURE_WEBAUTHN:
        case LIBRDP_FEATURE_RAIL:
        case LIBRDP_FEATURE_CR2:
        case LIBRDP_FEATURE_ECHO:
        case LIBRDP_FEATURE_TELEMETRY:
        case LIBRDP_FEATURE_MULTIPARTY:
        case LIBRDP_FEATURE_DESKTOP_COMPOSITION:
        case LIBRDP_FEATURE_DISPLAY_CONTROL:
        case LIBRDP_FEATURE_GEOMETRY_TRACKING:
        case LIBRDP_FEATURE_MULTITRANSPORT:
        case LIBRDP_FEATURE_UDP_TRANSPORT:
        case LIBRDP_FEATURE_UDP2_TRANSPORT:
            return 1;
        default:
            return 0;
    }
}

static int rdp_server_feature_needs_application_backend(librdp_feature feature)
{
    switch (feature)
    {
        case LIBRDP_FEATURE_MULTITRANSPORT:
        case LIBRDP_FEATURE_UDP_TRANSPORT:
        case LIBRDP_FEATURE_UDP2_TRANSPORT:
            return 0;
        case LIBRDP_FEATURE_AUDIO_OUTPUT:
        case LIBRDP_FEATURE_AUDIO_INPUT:
        case LIBRDP_FEATURE_VIDEO:
        case LIBRDP_FEATURE_CAMERA:
        case LIBRDP_FEATURE_SMARTCARD:
        case LIBRDP_FEATURE_USB:
        case LIBRDP_FEATURE_PNP:
        case LIBRDP_FEATURE_WEBAUTHN:
        case LIBRDP_FEATURE_RAIL:
        case LIBRDP_FEATURE_CR2:
        case LIBRDP_FEATURE_ECHO:
        case LIBRDP_FEATURE_TELEMETRY:
        case LIBRDP_FEATURE_MULTIPARTY:
        case LIBRDP_FEATURE_DESKTOP_COMPOSITION:
        case LIBRDP_FEATURE_DISPLAY_CONTROL:
        case LIBRDP_FEATURE_GEOMETRY_TRACKING:
            return 1;
        default:
            return 1;
    }
}

static int rdp_server_feature_provider_mask_valid(librdp_feature feature)
{
    uint32_t mask = (uint32_t)feature;
    uint32_t bit = 1u;

    if (!rdp_server_valid_feature_mask(feature))
        return 0;
    while (bit != 0)
    {
        if ((mask & bit) != 0 &&
            !rdp_server_feature_needs_application_backend((librdp_feature)bit))
            return 0;
        bit <<= 1u;
    }
    return 1;
}

static int rdp_server_listener_feature_backend_ready(const librdp_server* server, librdp_feature feature)
{
    if (!rdp_server_feature_has_runtime(feature))
        return 0;
    if (!rdp_server_feature_needs_application_backend(feature))
        return 1;
    return server && (server->backend_features & (uint32_t)feature) != 0;
}

static void rdp_server_fill_feature_status(uint32_t requested_features,
                                           librdp_feature feature,
                                           int backend_ready,
                                           librdp_feature_status* status)
{
    memset(status, 0, sizeof(*status));
    status->feature = feature;
    status->requested = (requested_features & (uint32_t)feature) != 0;
    status->built = rdp_server_feature_has_runtime(feature) ? 1 : 0;
    status->backend_ready = status->built && backend_ready ? 1 : 0;
    if (!status->requested)
        status->reason = LIBRDP_FEATURE_REASON_NOT_REQUESTED;
    else if (!status->built)
        status->reason = LIBRDP_FEATURE_REASON_NOT_BUILT;
    else if (!status->backend_ready)
        status->reason = LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE;
    else
        status->reason = LIBRDP_FEATURE_REASON_NOT_NEGOTIATED;
}

static char* rdp_server_strdup_bounded(const char* text)
{
    size_t length = 0;
    char* copy = NULL;

    if (!text)
        return NULL;
    length = strlen(text);
    if (length > RDP_SERVER_MAX_TEXT)
        return NULL;
    copy = (char*)malloc(length + 1u);
    if (!copy)
        return NULL;
    memcpy(copy, text, length + 1u);
    return copy;
}

static char* rdp_server_secure_strdup_bounded(const char* text)
{
    return rdp_server_strdup_bounded(text);
}

static void rdp_server_secure_free(char* text)
{
    if (!text)
        return;
    OPENSSL_cleanse(text, strlen(text));
    free(text);
}

static int rdp_server_config_valid(const librdp_server_config* config)
{
    if (!config || config->version != LIBRDP_SERVER_CONFIG_VERSION ||
        config->size < sizeof(librdp_server_config))
        return 0;
    if (config->backlog > RDP_SERVER_MAX_BACKLOG || config->max_peers > RDP_SERVER_MAX_PEERS)
        return 0;
    if (config->width > RDP_SERVER_MAX_DESKTOP_SIZE || config->height > RDP_SERVER_MAX_DESKTOP_SIZE)
        return 0;
    if ((config->width == 0) != (config->height == 0))
        return 0;
    if (config->security_mode != LIBRDP_SECURITY_AUTO &&
        config->security_mode != LIBRDP_SECURITY_STANDARD &&
        config->security_mode != LIBRDP_SECURITY_TLS &&
        config->security_mode != LIBRDP_SECURITY_NLA)
        return 0;
    if ((config->security_mode == LIBRDP_SECURITY_TLS || config->security_mode == LIBRDP_SECURITY_NLA) &&
        (!config->tls_certificate_path || !config->tls_private_key_path))
        return 0;
    if (config->security_mode == LIBRDP_SECURITY_NLA &&
        (!config->nla_username || config->nla_username[0] == '\0' ||
         !config->nla_password || config->nla_password[0] == '\0'))
        return 0;
    return 1;
}

librdp_status librdp_server_config_init(librdp_server_config* config)
{
    if (!config)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(config, 0, sizeof(*config));
    config->version = LIBRDP_SERVER_CONFIG_VERSION;
    config->size = (uint32_t)sizeof(*config);
    config->backlog = RDP_SERVER_DEFAULT_BACKLOG;
    config->max_peers = RDP_SERVER_DEFAULT_MAX_PEERS;
    config->width = RDP_SERVER_DEFAULT_WIDTH;
    config->height = RDP_SERVER_DEFAULT_HEIGHT;
    config->security_mode = LIBRDP_SECURITY_STANDARD;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_input_event_init(librdp_server_input_event* event)
{
    if (!event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(event, 0, sizeof(*event));
    event->version = LIBRDP_SERVER_INPUT_EVENT_VERSION;
    event->size = (uint32_t)sizeof(*event);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_static_channel_info_init(librdp_server_static_channel_info* info)
{
    if (!info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(info, 0, sizeof(*info));
    info->version = LIBRDP_SERVER_STATIC_CHANNEL_INFO_VERSION;
    info->size = (uint32_t)sizeof(*info);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_dynamic_channel_info_init(librdp_server_dynamic_channel_info* info)
{
    if (!info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(info, 0, sizeof(*info));
    info->version = LIBRDP_SERVER_DYNAMIC_CHANNEL_INFO_VERSION;
    info->size = (uint32_t)sizeof(*info);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_extension_event_init(librdp_server_extension_event* event)
{
    if (!event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(event, 0, sizeof(*event));
    event->version = LIBRDP_SERVER_EXTENSION_EVENT_VERSION;
    event->size = (uint32_t)sizeof(*event);
    event->status = LIBRDP_STATUS_OK;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_event_init(librdp_server_event* event)
{
    if (!event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(event, 0, sizeof(*event));
    event->version = LIBRDP_SERVER_EVENT_VERSION;
    event->size = (uint32_t)sizeof(*event);
    event->status = LIBRDP_STATUS_OK;
    event->component = LIBRDP_ERROR_COMPONENT_NONE;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_status_init(librdp_server_status* status)
{
    if (!status)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(status, 0, sizeof(*status));
    status->version = LIBRDP_SERVER_STATUS_VERSION;
    status->size = (uint32_t)sizeof(*status);
    status->status = LIBRDP_STATUS_OK;
    status->component = LIBRDP_ERROR_COMPONENT_NONE;
    status->state = LIBRDP_SERVER_PEER_NEW;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_metrics_init(librdp_server_metrics* metrics)
{
    if (!metrics)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(metrics, 0, sizeof(*metrics));
    metrics->version = LIBRDP_SERVER_METRICS_VERSION;
    metrics->size = (uint32_t)sizeof(*metrics);
    return LIBRDP_STATUS_OK;
}

static int rdp_server_status_valid(const librdp_server_status* status)
{
    return status && status->version == LIBRDP_SERVER_STATUS_VERSION &&
           status->size >= sizeof(librdp_server_status);
}

static void rdp_server_copy_token(char* output, size_t output_len, const char* input)
{
    size_t input_len = 0;

    if (!output || output_len == 0)
        return;
    output[0] = '\0';
    if (!input)
        return;
    input_len = strlen(input);
    if (input_len >= output_len)
        input_len = output_len - 1u;
    if (input_len > 0)
        memcpy(output, input, input_len);
    output[input_len] = '\0';
}

static librdp_error_component rdp_server_component_for_status(librdp_status status)
{
    if (status == LIBRDP_STATUS_IO_ERROR || status == LIBRDP_STATUS_CLOSED || status == LIBRDP_STATUS_TIMEOUT)
        return LIBRDP_ERROR_COMPONENT_TRANSPORT;
    if (status == LIBRDP_STATUS_LIMIT_EXCEEDED || status == LIBRDP_STATUS_PROTOCOL_ERROR ||
        status == LIBRDP_STATUS_UNSUPPORTED)
        return LIBRDP_ERROR_COMPONENT_PROTOCOL;
    return LIBRDP_ERROR_COMPONENT_CLIENT;
}

static void rdp_server_emit_event(librdp_server_peer* peer, const librdp_server_event* event)
{
    if (peer && event && peer->event_callback)
        peer->event_callback(peer, event, peer->event_callback_user_data);
}

static void rdp_server_set_state(librdp_server_peer* peer, librdp_server_peer_state state)
{
    librdp_server_event event;
    librdp_server_peer_state old_state = LIBRDP_SERVER_PEER_FAILED;

    if (!peer || peer->state == state)
        return;
    old_state = peer->state;
    peer->state = state;
    if (librdp_server_event_init(&event) != LIBRDP_STATUS_OK)
        return;
    event.type = LIBRDP_SERVER_EVENT_STATE_CHANGED;
    event.old_state = old_state;
    event.new_state = state;
    rdp_server_emit_event(peer, &event);
}

static void rdp_server_record_status(librdp_server_peer* peer,
                                     librdp_status status,
                                     librdp_error_component component,
                                     const char* phase,
                                     const char* message)
{
    librdp_server_event event;

    if (!peer)
        return;
    if (librdp_server_status_init(&peer->last_status) != LIBRDP_STATUS_OK)
        return;
    peer->last_status.status = status;
    peer->last_status.component = component;
    peer->last_status.state = peer->state;
    rdp_server_copy_token(peer->last_status.phase, sizeof(peer->last_status.phase), phase);
    rdp_server_copy_token(peer->last_status.message, sizeof(peer->last_status.message), message);
    if (status == LIBRDP_STATUS_OK || status == LIBRDP_STATUS_TIMEOUT)
        return;
    if (librdp_server_event_init(&event) != LIBRDP_STATUS_OK)
        return;
    event.type = LIBRDP_SERVER_EVENT_ERROR;
    event.status = status;
    event.component = component;
    event.phase = peer->last_status.phase;
    event.message = peer->last_status.message;
    rdp_server_emit_event(peer, &event);
}

static void rdp_server_emit_surface_event(librdp_server_peer* peer,
                                          uint32_t x,
                                          uint32_t y,
                                          uint32_t width,
                                          uint32_t height)
{
    librdp_server_event event;

    if (!peer || librdp_server_event_init(&event) != LIBRDP_STATUS_OK)
        return;
    event.type = LIBRDP_SERVER_EVENT_SURFACE;
    event.x = x;
    event.y = y;
    event.width = width;
    event.height = height;
    rdp_server_emit_event(peer, &event);
}

static void rdp_server_emit_channel_joined_event(librdp_server_peer* peer, uint16_t channel_id)
{
    librdp_server_event event;

    if (!peer || librdp_server_event_init(&event) != LIBRDP_STATUS_OK)
        return;
    event.type = LIBRDP_SERVER_EVENT_CHANNEL_JOINED;
    event.channel_id = channel_id;
    rdp_server_emit_event(peer, &event);
}

static librdp_status rdp_server_read_u32_le(const uint8_t* data, size_t data_len, uint32_t* value)
{
    rdp_stream stream;

    if (!data || !value || data_len < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&stream, data, data_len);
    return rdp_stream_read_u32_le(&stream, value);
}

static int rdp_server_name_equals(const char* name, size_t name_len, const char* expected)
{
    size_t expected_len = expected ? strlen(expected) : 0;

    return name && expected && name_len == expected_len && memcmp(name, expected, expected_len) == 0;
}

static librdp_server_extension_family rdp_server_redirected_device_family(uint32_t device_type,
                                                                          librdp_feature* feature)
{
    if (feature)
        *feature = (librdp_feature)0;
    switch (device_type)
    {
        case RDP_DEVICE_REDIRECTION_TYPE_FILESYSTEM:
            return LIBRDP_SERVER_EXTENSION_FILESYSTEM;
        case RDP_DEVICE_REDIRECTION_TYPE_PRINTER:
            return LIBRDP_SERVER_EXTENSION_PRINTER;
        case RDP_DEVICE_REDIRECTION_TYPE_SERIAL:
            return LIBRDP_SERVER_EXTENSION_SERIAL_PORT;
        case RDP_DEVICE_REDIRECTION_TYPE_PARALLEL:
            return LIBRDP_SERVER_EXTENSION_PARALLEL_PORT;
        case RDP_DEVICE_REDIRECTION_TYPE_SMARTCARD:
            if (feature)
                *feature = LIBRDP_FEATURE_SMARTCARD;
            return LIBRDP_SERVER_EXTENSION_SMARTCARD;
        default:
            return LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION;
    }
}

static rdp_server_redirected_device* rdp_server_find_redirected_device(librdp_server_peer* peer,
                                                                       uint32_t device_id)
{
    if (!peer)
        return NULL;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_REDIRECTED_DEVICES; i++)
    {
        if (peer->redirected_devices[i].present && peer->redirected_devices[i].device_id == device_id)
            return &peer->redirected_devices[i];
    }
    return NULL;
}

static const rdp_server_redirected_device* rdp_server_find_redirected_device_const(
    const librdp_server_peer* peer,
    uint32_t device_id)
{
    if (!peer)
        return NULL;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_REDIRECTED_DEVICES; i++)
    {
        if (peer->redirected_devices[i].present && peer->redirected_devices[i].device_id == device_id)
            return &peer->redirected_devices[i];
    }
    return NULL;
}

static librdp_status rdp_server_store_redirected_device(librdp_server_peer* peer,
                                                        uint32_t device_id,
                                                        uint32_t device_type)
{
    rdp_server_redirected_device* slot = rdp_server_find_redirected_device(peer, device_id);

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (slot)
    {
        slot->device_type = device_type;
        return LIBRDP_STATUS_OK;
    }
    if (peer->redirected_device_count >= RDP_SERVER_MAX_REDIRECTED_DEVICES)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_REDIRECTED_DEVICES; i++)
    {
        if (!peer->redirected_devices[i].present)
        {
            peer->redirected_devices[i].present = 1;
            peer->redirected_devices[i].device_id = device_id;
            peer->redirected_devices[i].device_type = device_type;
            peer->redirected_device_count++;
            return LIBRDP_STATUS_OK;
        }
    }
    return LIBRDP_STATUS_LIMIT_EXCEEDED;
}

static void rdp_server_remove_redirected_device(librdp_server_peer* peer, uint32_t device_id)
{
    rdp_server_redirected_device* slot = rdp_server_find_redirected_device(peer, device_id);

    if (!peer || !slot)
        return;
    memset(slot, 0, sizeof(*slot));
    if (peer->redirected_device_count > 0)
        peer->redirected_device_count--;
}

static void rdp_server_classify_device_payload(const librdp_server_peer* peer,
                                               const uint8_t* data,
                                               size_t data_len,
                                               librdp_server_extension_family* family,
                                               librdp_feature* feature)
{
    rdp_device_redirection_header header;
    uint32_t device_id = 0;
    const rdp_server_redirected_device* device = NULL;

    if (!peer || !data || !family || !feature ||
        rdp_device_redirection_parse_header(data, data_len, &header) != LIBRDP_STATUS_OK)
        return;
    if (header.component == RDP_DEVICE_REDIRECTION_COMPONENT_PRINTER)
    {
        *family = LIBRDP_SERVER_EXTENSION_PRINTER;
        return;
    }
    if (header.component != RDP_DEVICE_REDIRECTION_COMPONENT_CORE)
        return;
    if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOREQUEST)
    {
        rdp_device_redirection_io_request request;

        if (rdp_device_redirection_parse_io_request(data, data_len, &request) != LIBRDP_STATUS_OK)
            return;
        device_id = request.device_id;
    }
    else if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOCOMPLETION)
    {
        rdp_device_redirection_io_completion completion;

        if (rdp_device_redirection_parse_io_completion(data, data_len, &completion) != LIBRDP_STATUS_OK)
            return;
        device_id = completion.device_id;
    }
    else if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_REPLY)
    {
        rdp_device_redirection_device_reply reply;

        if (rdp_device_redirection_parse_device_reply(data, data_len, &reply) != LIBRDP_STATUS_OK)
            return;
        device_id = reply.device_id;
    }
    else
        return;
    device = rdp_server_find_redirected_device_const(peer, device_id);
    if (device)
        *family = rdp_server_redirected_device_family(device->device_type, feature);
}

static librdp_status rdp_server_update_redirected_devices(librdp_server_peer* peer,
                                                          const librdp_server_extension_event* event)
{
    rdp_device_redirection_header header;

    if (!peer || !event || !event->payload ||
        (event->family != LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION &&
         event->family != LIBRDP_SERVER_EXTENSION_FILESYSTEM &&
         event->family != LIBRDP_SERVER_EXTENSION_PRINTER &&
         event->family != LIBRDP_SERVER_EXTENSION_SERIAL_PORT &&
         event->family != LIBRDP_SERVER_EXTENSION_PARALLEL_PORT &&
         event->family != LIBRDP_SERVER_EXTENSION_SMARTCARD))
        return LIBRDP_STATUS_OK;
    if (rdp_device_redirection_parse_header(event->payload, event->payload_len, &header) != LIBRDP_STATUS_OK ||
        header.component != RDP_DEVICE_REDIRECTION_COMPONENT_CORE)
        return LIBRDP_STATUS_OK;
    if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICELIST_ANNOUNCE)
    {
        rdp_device_redirection_device_list list;

        if (rdp_device_redirection_parse_device_list_announce(event->payload,
                                                              event->payload_len,
                                                              &list) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        for (uint32_t i = 0; i < list.count; i++)
        {
            librdp_status status = rdp_server_store_redirected_device(peer,
                                                                      list.devices[i].device_id,
                                                                      list.devices[i].device_type);

            if (status != LIBRDP_STATUS_OK)
                return status;
        }
    }
    else if (header.packet_id == RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICELIST_REMOVE)
    {
        rdp_device_redirection_device_remove remove;

        if (rdp_device_redirection_parse_device_remove(event->payload,
                                                       event->payload_len,
                                                       &remove) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        for (uint32_t i = 0; i < remove.count; i++)
            rdp_server_remove_redirected_device(peer, remove.device_ids[i]);
    }
    return LIBRDP_STATUS_OK;
}

static void rdp_server_extension_classify_name(const char* name,
                                               size_t name_len,
                                               librdp_server_extension_family* family,
                                               librdp_feature* feature)
{
    *family = LIBRDP_SERVER_EXTENSION_UNKNOWN;
    *feature = (librdp_feature)0;
    if (rdp_server_name_equals(name, name_len, RDP_SERVER_CLIPBOARD_CHANNEL_NAME))
        *family = LIBRDP_SERVER_EXTENSION_CLIPBOARD;
    else if (rdp_server_name_equals(name, name_len, RDP_DEVICE_REDIRECTION_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION;
        *feature = (librdp_feature)(LIBRDP_FEATURE_SMARTCARD |
                                    LIBRDP_FEATURE_PNP);
    }
    else if (rdp_server_name_equals(name, name_len, RDP_AUDIO_OUTPUT_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_AUDIO_OUTPUT;
        *feature = LIBRDP_FEATURE_AUDIO_OUTPUT;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_AUDIO_INPUT_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_AUDIO_INPUT;
        *feature = LIBRDP_FEATURE_AUDIO_INPUT;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_VIDEO_REDIRECTION_CHANNEL_NAME) ||
             rdp_server_name_equals(name, name_len, RDP_VIDEO_OPTIMIZED_CONTROL_CHANNEL) ||
             rdp_server_name_equals(name, name_len, RDP_VIDEO_OPTIMIZED_DATA_CHANNEL))
    {
        *family = LIBRDP_SERVER_EXTENSION_VIDEO;
        *feature = LIBRDP_FEATURE_VIDEO;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_VIDEO_CAPTURE_CONTROL_CHANNEL_NAME) ||
             rdp_server_name_equals(name, name_len, RDP_VIDEO_CAPTURE_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_CAMERA;
        *feature = LIBRDP_FEATURE_CAMERA;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_USB_REDIRECTION_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_USB;
        *feature = LIBRDP_FEATURE_USB;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_WEBAUTHN_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_WEBAUTHN;
        *feature = LIBRDP_FEATURE_WEBAUTHN;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_REMOTE_PROGRAMS_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_RAIL;
        *feature = LIBRDP_FEATURE_RAIL;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_COMPOSITED_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_CR2;
        *feature = LIBRDP_FEATURE_CR2;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_ECHO_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_ECHO;
        *feature = LIBRDP_FEATURE_ECHO;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_DISPLAY_CONTROL_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_DISPLAY_CONTROL;
        *feature = LIBRDP_FEATURE_DISPLAY_CONTROL;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_GRAPHICS_PIPELINE_CHANNEL_NAME))
        *family = LIBRDP_SERVER_EXTENSION_GRAPHICS;
    else if (rdp_server_name_equals(name, name_len, RDP_CORE_INPUT_CHANNEL_NAME))
        *family = LIBRDP_SERVER_EXTENSION_CORE_INPUT;
    else if (rdp_server_name_equals(name, name_len, RDP_INPUT_CHANNEL_NAME))
        *family = LIBRDP_SERVER_EXTENSION_TOUCH_INPUT;
    else if (rdp_server_name_equals(name, name_len, RDP_MOUSE_CURSOR_CHANNEL_NAME))
        *family = LIBRDP_SERVER_EXTENSION_MOUSE_CURSOR;
    else if (rdp_server_name_equals(name, name_len, RDP_AUTH_REDIRECTION_CHANNEL_NAME))
        *family = LIBRDP_SERVER_EXTENSION_AUTH_REDIRECTION;
    else if (rdp_server_name_equals(name, name_len, RDP_TELEMETRY_CHANNEL_NAME) ||
             rdp_server_name_equals(name, name_len, RDP_TELEMETRY_DVC_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_TELEMETRY;
        *feature = LIBRDP_FEATURE_TELEMETRY;
    }
    else if (rdp_server_name_equals(name, name_len, RDP_MULTIPARTY_CHANNEL_NAME))
    {
        *family = LIBRDP_SERVER_EXTENSION_MULTIPARTY;
        *feature = LIBRDP_FEATURE_MULTIPARTY;
    }
}

/*
 * Validate the outer PDU for a known server extension and extract stable
 * metadata for the public extension callback. This deliberately stops at
 * header-level fields so sensitive payloads remain borrowed and opaque; a
 * malformed known extension returns the parser status and prevents raw data
 * from being accepted as a valid runtime message.
 */
static librdp_status rdp_server_extension_validate(librdp_server_extension_event* event)
{
    switch (event->family)
    {
        case LIBRDP_SERVER_EXTENSION_CLIPBOARD:
        {
            rdp_clipboard_packet packet;
            librdp_status status = rdp_clipboard_parse_packet(event->payload, event->payload_len, &packet);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = packet.type;
                event->flags = packet.flags;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION:
        case LIBRDP_SERVER_EXTENSION_FILESYSTEM:
        case LIBRDP_SERVER_EXTENSION_PRINTER:
        case LIBRDP_SERVER_EXTENSION_SERIAL_PORT:
        case LIBRDP_SERVER_EXTENSION_PARALLEL_PORT:
        case LIBRDP_SERVER_EXTENSION_SMARTCARD:
        {
            rdp_device_redirection_header header;
            librdp_status status = rdp_device_redirection_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.packet_id;
                event->flags = header.component;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_AUDIO_OUTPUT:
        {
            rdp_audio_output_header header;
            librdp_status status = rdp_audio_output_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.msg_type;
                event->flags = header.pad;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_AUDIO_INPUT:
        {
            rdp_audio_input_header header;
            librdp_status status = rdp_audio_input_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
                event->message_type = header.message_id;
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_VIDEO:
            if (rdp_server_name_equals(event->name, event->name_len, RDP_VIDEO_REDIRECTION_CHANNEL_NAME))
            {
                rdp_video_redirection_header header;
                librdp_status status =
                    rdp_video_redirection_parse_header(event->payload, event->payload_len, 1, &header);
                if (status != LIBRDP_STATUS_OK)
                    status = rdp_video_redirection_parse_header(event->payload, event->payload_len, 0, &header);
                if (status == LIBRDP_STATUS_OK)
                {
                    event->message_type = header.message_id;
                    event->flags = header.interface_id;
                }
                return status;
            }
            {
                rdp_video_optimized_header header;
                librdp_status status =
                    rdp_video_optimized_parse_header(event->payload, event->payload_len, &header);
                if (status == LIBRDP_STATUS_OK)
                    event->message_type = header.packet_type;
                return status;
            }
        case LIBRDP_SERVER_EXTENSION_CAMERA:
        {
            rdp_video_capture_header header;
            librdp_status status = rdp_video_capture_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.message_id;
                event->flags = header.version;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_USB:
        {
            rdp_usb_redirection_header header;
            librdp_status status =
                rdp_usb_redirection_parse_header(event->payload, event->payload_len, 1, &header);
            if (status != LIBRDP_STATUS_OK)
                status = rdp_usb_redirection_parse_header(event->payload, event->payload_len, 0, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.has_function_id ? header.function_id : header.message_id;
                event->flags = header.interface_id;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_WEBAUTHN:
        {
            rdp_webauthn_request request;
            rdp_webauthn_response response;
            librdp_status status = rdp_webauthn_parse_request(event->payload, event->payload_len, &request);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = request.command;
                event->flags = request.flags;
                return LIBRDP_STATUS_OK;
            }
            status = rdp_webauthn_parse_response(event->payload, event->payload_len, &response);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = response.hresult;
                event->flags = 1u;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_RAIL:
        {
            rdp_remote_programs_header header;
            librdp_status status = rdp_remote_programs_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.order_type;
                event->flags = header.order_length;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_CR2:
        {
            rdp_composited_channel_message message;
            librdp_status status =
                rdp_composited_parse_channel_message(event->payload, event->payload_len, &message);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = message.control_code;
                event->flags = message.message_size;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_ECHO:
        {
            rdp_echo_channel_pdu pdu;
            librdp_status status = rdp_echo_channel_parse_request(event->payload, event->payload_len, &pdu);
            if (status == LIBRDP_STATUS_OK)
                event->message_type = 1u;
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_DISPLAY_CONTROL:
        {
            uint32_t pdu_type = 0;
            librdp_status status = rdp_server_read_u32_le(event->payload, event->payload_len, &pdu_type);
            if (status == LIBRDP_STATUS_OK)
                event->message_type = pdu_type;
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_GRAPHICS:
        {
            rdp_graphics_header header;
            librdp_status status = rdp_graphics_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.cmd_id;
                event->flags = header.flags;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_CORE_INPUT:
        {
            rdp_core_input_header header;
            librdp_status status = rdp_core_input_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.pdu_type;
                event->flags = header.event_count;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_TOUCH_INPUT:
        {
            rdp_input_channel_header header;
            librdp_status status = rdp_input_channel_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.event_id;
                event->flags = header.pdu_length;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_MOUSE_CURSOR:
        {
            rdp_mouse_cursor_header header;
            librdp_status status = rdp_mouse_cursor_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.pdu_type;
                event->flags = header.update_type;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_AUTH_REDIRECTION:
        {
            rdp_auth_redirection_call_message call;
            rdp_auth_redirection_response_message response;
            librdp_status status =
                rdp_auth_redirection_parse_call_message(event->payload, event->payload_len, &call);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = call.call.call_id;
                return LIBRDP_STATUS_OK;
            }
            status = rdp_auth_redirection_parse_response_message(event->payload, event->payload_len, &response);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = response.response.call_id;
                event->flags = response.response.status;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_TELEMETRY:
        {
            rdp_telemetry_pdu pdu;
            librdp_status status = rdp_telemetry_parse_pdu(event->payload, event->payload_len, &pdu);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = pdu.id;
                event->flags = pdu.length;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_DESKTOP_COMPOSITION:
        {
            rdp_desktop_composition_header header;
            librdp_status status =
                rdp_desktop_composition_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.operation;
                event->flags = header.size;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_MULTIPARTY:
        {
            rdp_multiparty_header header;
            librdp_status status = rdp_multiparty_parse_header(event->payload, event->payload_len, &header);
            if (status == LIBRDP_STATUS_OK)
            {
                event->message_type = header.type;
                event->flags = header.length;
            }
            return status;
        }
        case LIBRDP_SERVER_EXTENSION_UNKNOWN:
        case LIBRDP_SERVER_EXTENSION_PNP:
        default:
            return LIBRDP_STATUS_OK;
    }
}

static librdp_status rdp_server_emit_extension_event(librdp_server_peer* peer,
                                                     const char* name,
                                                     size_t name_len,
                                                     uint16_t channel_id,
                                                     uint32_t dynamic_channel_id,
                                                     uint8_t dynamic_priority,
                                                     const uint8_t* data,
                                                     size_t data_len)
{
    librdp_server_extension_event event;

    if (!peer || !name || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (librdp_server_extension_event_init(&event) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    event.channel_id = channel_id;
    event.dynamic_channel_id = dynamic_channel_id;
    event.dynamic_priority = dynamic_priority;
    event.name = name;
    event.name_len = name_len;
    event.payload = data;
    event.payload_len = data_len;
    rdp_server_extension_classify_name(name, name_len, &event.family, &event.feature);
    if (event.family == LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION)
        rdp_server_classify_device_payload(peer, data, data_len, &event.family, &event.feature);
    event.status = rdp_server_extension_validate(&event);
    if (event.status == LIBRDP_STATUS_OK)
        event.status = rdp_server_update_redirected_devices(peer, &event);
    if (event.family != LIBRDP_SERVER_EXTENSION_UNKNOWN &&
        event.status == LIBRDP_STATUS_OK &&
        peer->extension_callback)
        peer->extension_callback(peer, &event, peer->extension_callback_user_data);
    return event.status;
}

librdp_server* librdp_server_new(const librdp_server_config* config)
{
    librdp_server* server = NULL;

    if (!rdp_server_config_valid(config))
        return NULL;
    server = (librdp_server*)calloc(1u, sizeof(*server));
    if (!server)
        return NULL;
    if (config->bind_address)
    {
        server->bind_address = rdp_server_strdup_bounded(config->bind_address);
        if (!server->bind_address)
        {
            librdp_server_free(server);
            return NULL;
        }
    }
    if (config->server_name)
    {
        server->server_name = rdp_server_strdup_bounded(config->server_name);
        if (!server->server_name)
        {
            librdp_server_free(server);
            return NULL;
        }
    }
    if (config->tls_certificate_path)
    {
        server->tls_certificate_path = rdp_server_strdup_bounded(config->tls_certificate_path);
        if (!server->tls_certificate_path)
        {
            librdp_server_free(server);
            return NULL;
        }
    }
    if (config->tls_private_key_path)
    {
        server->tls_private_key_path = rdp_server_strdup_bounded(config->tls_private_key_path);
        if (!server->tls_private_key_path)
        {
            librdp_server_free(server);
            return NULL;
        }
    }
    if (config->nla_domain)
    {
        server->nla_domain = rdp_server_strdup_bounded(config->nla_domain);
        if (!server->nla_domain)
        {
            librdp_server_free(server);
            return NULL;
        }
    }
    if (config->nla_username)
    {
        server->nla_username = rdp_server_strdup_bounded(config->nla_username);
        if (!server->nla_username)
        {
            librdp_server_free(server);
            return NULL;
        }
    }
    if (config->nla_password)
    {
        server->nla_password = rdp_server_secure_strdup_bounded(config->nla_password);
        if (!server->nla_password)
        {
            librdp_server_free(server);
            return NULL;
        }
    }
    server->port = config->port;
    server->backlog = config->backlog ? config->backlog : RDP_SERVER_DEFAULT_BACKLOG;
    server->max_peers = config->max_peers ? config->max_peers : RDP_SERVER_DEFAULT_MAX_PEERS;
    server->width = config->width ? config->width : RDP_SERVER_DEFAULT_WIDTH;
    server->height = config->height ? config->height : RDP_SERVER_DEFAULT_HEIGHT;
    server->security_mode = config->security_mode;
    server->listen_fd = -1;
    return server;
}

void librdp_server_free(librdp_server* server)
{
    if (!server)
        return;
    librdp_server_close(server);
    free(server->bind_address);
    free(server->server_name);
    free(server->tls_certificate_path);
    free(server->tls_private_key_path);
    free(server->nla_domain);
    free(server->nla_username);
    rdp_server_secure_free(server->nla_password);
    free(server);
}

/*
 * Bind one resolved address and transfer the resulting socket to the server
 * only after non-blocking setup, bind, listen, and local-port discovery all
 * succeed.
 */
static librdp_status rdp_server_bind_address(librdp_server* server, const struct addrinfo* address)
{
    int fd = -1;
    int reuse = 1;
    struct sockaddr_storage local;
    socklen_t local_len = (socklen_t)sizeof(local);

    fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (fd < 0)
        return LIBRDP_STATUS_IO_ERROR;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (rdp_socket_set_nonblocking(fd, 1) != 0 ||
        bind(fd, address->ai_addr, address->ai_addrlen) != 0 ||
        listen(fd, (int)server->backlog) != 0 ||
        getsockname(fd, (struct sockaddr*)&local, &local_len) != 0)
    {
        rdp_socket_close(fd);
        return LIBRDP_STATUS_IO_ERROR;
    }
    if (local.ss_family == AF_INET)
        server->local_port = ntohs(((const struct sockaddr_in*)&local)->sin_port);
    else if (local.ss_family == AF_INET6)
        server->local_port = ntohs(((const struct sockaddr_in6*)&local)->sin6_port);
    else
    {
        rdp_socket_close(fd);
        return LIBRDP_STATUS_IO_ERROR;
    }
    server->accepted_peers = 0;
    server->listen_fd = fd;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_listen(librdp_server* server)
{
    struct addrinfo hints;
    struct addrinfo* addresses = NULL;
    struct addrinfo* it = NULL;
    char service[16];
    const char* bind_address = NULL;
    librdp_status status = LIBRDP_STATUS_IO_ERROR;

    if (!server)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (server->listen_fd >= 0)
        return LIBRDP_STATUS_STATE;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    bind_address = server->bind_address ? server->bind_address : "127.0.0.1";
    (void)snprintf(service, sizeof(service), "%u", (unsigned)server->port);
    if (getaddrinfo(bind_address, service, &hints, &addresses) != 0)
        return LIBRDP_STATUS_IO_ERROR;
    for (it = addresses; it; it = it->ai_next)
    {
        status = rdp_server_bind_address(server, it);
        if (status == LIBRDP_STATUS_OK)
            break;
    }
    freeaddrinfo(addresses);
    return status;
}

void librdp_server_close(librdp_server* server)
{
    if (!server)
        return;
    if (server->listen_fd >= 0)
    {
        rdp_socket_close(server->listen_fd);
        server->listen_fd = -1;
    }
    server->local_port = 0;
}

uint16_t librdp_server_local_port(const librdp_server* server)
{
    if (!server || server->listen_fd < 0)
        return 0;
    return server->local_port;
}

librdp_status librdp_server_enable_feature(librdp_server* server, librdp_feature feature, int enabled)
{
    if (!server || !rdp_server_valid_feature_mask(feature))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (server->listen_fd >= 0)
        return LIBRDP_STATUS_STATE;
    if (enabled)
        server->requested_features |= (uint32_t)feature;
    else
        server->requested_features &= ~((uint32_t)feature);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_enable_feature_provider(librdp_server* server,
                                                    librdp_feature feature,
                                                    int enabled)
{
    if (!server || !rdp_server_valid_feature_mask(feature))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_server_feature_provider_mask_valid(feature))
        return LIBRDP_STATUS_UNSUPPORTED;
    if (server->listen_fd >= 0)
        return LIBRDP_STATUS_STATE;
    if (enabled)
        server->backend_features |= (uint32_t)feature;
    else
        server->backend_features &= ~(uint32_t)feature;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_get_feature_status(const librdp_server* server,
                                               librdp_feature feature,
                                               librdp_feature_status* status)
{
    if (!server || !status || !rdp_server_valid_single_feature(feature))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_server_fill_feature_status(server->requested_features,
                                   feature,
                                   rdp_server_listener_feature_backend_ready(server, feature),
                                   status);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_get_pollfds(librdp_server* server,
                                        struct pollfd* fds,
                                        size_t capacity,
                                        size_t* count)
{
    if (!server || !count || (!fds && capacity > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (server->listen_fd < 0)
        return LIBRDP_STATUS_STATE;
    *count = 1;
    if (capacity == 0)
        return LIBRDP_STATUS_OK;
    if (capacity < 1)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&fds[0], 0, sizeof(fds[0]));
    fds[0].fd = server->listen_fd;
    fds[0].events = POLLIN;
    return LIBRDP_STATUS_OK;
}

/*
 * Purpose: accept exactly one TCP peer and transfer a copied listener
 * configuration into peer-owned state. Invariants: the peer is visible to the
 * caller only after socket setup, dynamic-channel state, status, metrics, and
 * security buffers are initialized. Failure policy: partially allocated peers
 * and sensitive NLA password copies are released through librdp_server_peer_free().
 */
librdp_status librdp_server_accept(librdp_server* server, int timeout_ms, librdp_server_peer** peer)
{
    struct pollfd pfd;
    int rc = 0;
    int fd = -1;
    librdp_server_peer* accepted = NULL;

    if (!server || !peer || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *peer = NULL;
    if (server->listen_fd < 0)
        return LIBRDP_STATUS_STATE;
    if (server->accepted_peers >= server->max_peers)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    pfd.fd = server->listen_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    rc = poll(&pfd, 1, timeout_ms);
    if (rc == 0)
        return LIBRDP_STATUS_TIMEOUT;
    if (rc < 0)
        return errno == EINTR ? LIBRDP_STATUS_TIMEOUT : LIBRDP_STATUS_IO_ERROR;
    fd = accept(server->listen_fd, NULL, NULL);
    if (fd < 0)
        return errno == EAGAIN || errno == EWOULDBLOCK ? LIBRDP_STATUS_TIMEOUT : LIBRDP_STATUS_IO_ERROR;
    if (rdp_socket_set_nonblocking(fd, 1) != 0)
    {
        rdp_socket_close(fd);
        return LIBRDP_STATUS_IO_ERROR;
    }
    (void)rdp_socket_set_nodelay(fd);
    accepted = (librdp_server_peer*)calloc(1u, sizeof(*accepted));
    if (!accepted)
    {
        rdp_socket_close(fd);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    accepted->fd = fd;
    accepted->state = LIBRDP_SERVER_PEER_NEW;
    accepted->share_id = 0x00010001u;
    accepted->user_id = (uint16_t)RDP_MCS_BASE_CHANNEL_ID;
    accepted->width = (uint16_t)server->width;
    accepted->height = (uint16_t)server->height;
    accepted->requested_features = server->requested_features;
    accepted->backend_features = server->backend_features;
    accepted->security_mode = server->security_mode;
    accepted->pending_revents = 0;
    rdp_server_dynamic_channels_reset(accepted);
    if (server->server_name)
    {
        accepted->server_name = rdp_server_strdup_bounded(server->server_name);
        if (!accepted->server_name)
        {
            free(accepted);
            rdp_socket_close(fd);
            return LIBRDP_STATUS_NO_MEMORY;
        }
    }
    if (server->tls_certificate_path)
    {
        accepted->tls_certificate_path = rdp_server_strdup_bounded(server->tls_certificate_path);
        if (!accepted->tls_certificate_path)
        {
            librdp_server_peer_free(accepted);
            return LIBRDP_STATUS_NO_MEMORY;
        }
    }
    if (server->tls_private_key_path)
    {
        accepted->tls_private_key_path = rdp_server_strdup_bounded(server->tls_private_key_path);
        if (!accepted->tls_private_key_path)
        {
            librdp_server_peer_free(accepted);
            return LIBRDP_STATUS_NO_MEMORY;
        }
    }
    if (server->nla_domain)
    {
        accepted->nla_domain = rdp_server_strdup_bounded(server->nla_domain);
        if (!accepted->nla_domain)
        {
            librdp_server_peer_free(accepted);
            return LIBRDP_STATUS_NO_MEMORY;
        }
    }
    if (server->nla_username)
    {
        accepted->nla_username = rdp_server_strdup_bounded(server->nla_username);
        if (!accepted->nla_username)
        {
            librdp_server_peer_free(accepted);
            return LIBRDP_STATUS_NO_MEMORY;
        }
    }
    if (server->nla_password)
    {
        accepted->nla_password = rdp_server_secure_strdup_bounded(server->nla_password);
        if (!accepted->nla_password)
        {
            librdp_server_peer_free(accepted);
            return LIBRDP_STATUS_NO_MEMORY;
        }
    }
    (void)librdp_server_metrics_init(&accepted->metrics);
    (void)librdp_server_status_init(&accepted->last_status);
    rdp_buffer_init(&accepted->input);
    rdp_buffer_init(&accepted->standard_certificate);
    rdp_buffer_init(&accepted->credssp_target_name);
    rdp_buffer_init(&accepted->credssp_target_info);
    *peer = accepted;
    server->accepted_peers++;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_send_all(int fd, const uint8_t* data, size_t length)
{
    size_t offset = 0;

    while (offset < length)
    {
        ssize_t written = send(fd, data + offset, length - offset, 0);

        if (written > 0)
        {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            struct pollfd pfd;
            int rc = 0;

            pfd.fd = fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            rc = poll(&pfd, 1, 1000);
            if (rc == 0)
                return LIBRDP_STATUS_TIMEOUT;
            if (rc < 0 && errno == EINTR)
                continue;
            if (rc < 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)))
                return LIBRDP_STATUS_IO_ERROR;
            continue;
        }
        return LIBRDP_STATUS_IO_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_wait_fd(int fd, short events, int timeout_ms)
{
    struct pollfd pfd;
    int rc = 0;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = events;
    do
    {
        rc = poll(&pfd, 1, timeout_ms);
    } while (rc < 0 && errno == EINTR);
    if (rc == 0)
        return LIBRDP_STATUS_TIMEOUT;
    if (rc < 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)))
        return LIBRDP_STATUS_IO_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_tls_status(SSL* tls, int rc, short* wait_events)
{
    int error = SSL_get_error(tls, rc);

    if (error == SSL_ERROR_ZERO_RETURN)
        return LIBRDP_STATUS_CLOSED;
    if (error == SSL_ERROR_WANT_READ)
    {
        if (wait_events)
            *wait_events = POLLIN;
        return LIBRDP_STATUS_AGAIN;
    }
    if (error == SSL_ERROR_WANT_WRITE)
    {
        if (wait_events)
            *wait_events = POLLOUT;
        return LIBRDP_STATUS_AGAIN;
    }
    return LIBRDP_STATUS_TLS_HANDSHAKE_FAILED;
}

static librdp_status rdp_server_tls_send_all(librdp_server_peer* peer, const uint8_t* data, size_t length)
{
    size_t offset = 0;

    while (offset < length)
    {
        int chunk = (length - offset) > (size_t)INT32_MAX ? INT32_MAX : (int)(length - offset);
        int written = SSL_write(peer->tls, data + offset, chunk);

        if (written > 0)
        {
            offset += (size_t)written;
            continue;
        }
        else
        {
            short wait_events = 0;
            librdp_status status = rdp_server_tls_status(peer->tls, written, &wait_events);

            if (status != LIBRDP_STATUS_AGAIN)
                return status;
            status = rdp_server_wait_fd(peer->fd, wait_events, 1000);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_peer_send_all(librdp_server_peer* peer, const uint8_t* data, size_t length)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = peer->tls_active ? rdp_server_tls_send_all(peer, data, length)
                              : rdp_server_send_all(peer->fd, data, length);
    if (status == LIBRDP_STATUS_OK)
        rdp_server_metric_add(&peer->metrics.bytes_written, (uint64_t)length);
    return status;
}

static librdp_status rdp_server_send_x224_data(librdp_server_peer* peer, const void* payload, size_t payload_len)
{
    rdp_buffer x224;
    rdp_buffer tpkt;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&x224);
    rdp_buffer_init(&tpkt);
    status = rdp_x224_wrap_data(&x224, payload, payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_tpkt_write(&tpkt, x224.data, x224.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_peer_send_all(peer, tpkt.data, tpkt.length);
    rdp_buffer_free(&tpkt);
    rdp_buffer_free(&x224);
    return status;
}

static librdp_status rdp_server_send_mcs_pdu(librdp_server_peer* peer, const rdp_buffer* mcs_pdu)
{
    if (!peer || !mcs_pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    librdp_status status = rdp_server_send_x224_data(peer, mcs_pdu->data, mcs_pdu->length);

    if (status == LIBRDP_STATUS_OK)
        rdp_server_metric_add(&peer->metrics.pdu_out, 1u);
    return status;
}

static librdp_status rdp_server_send_slowpath(librdp_server_peer* peer, const rdp_buffer* slowpath_pdu)
{
    rdp_buffer mcs;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !slowpath_pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&mcs);
    status = rdp_mcs_write_send_data_indication(&mcs,
                                                peer->user_id,
                                                (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                slowpath_pdu->data,
                                                slowpath_pdu->length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_mcs_pdu(peer, &mcs);
    rdp_buffer_free(&mcs);
    return status;
}

static void rdp_server_close_peer(librdp_server_peer* peer, librdp_server_peer_state state)
{
    if (!peer)
        return;
    if (peer->tls)
    {
        SSL_set_quiet_shutdown(peer->tls, 1);
        (void)SSL_shutdown(peer->tls);
        SSL_free(peer->tls);
        peer->tls = NULL;
    }
    if (peer->tls_context)
    {
        SSL_CTX_free(peer->tls_context);
        peer->tls_context = NULL;
    }
    peer->tls_active = 0;
    if (peer->fd >= 0)
    {
        rdp_socket_close(peer->fd);
        peer->fd = -1;
    }
    rdp_server_set_state(peer, state);
}

static librdp_status rdp_server_send_x224_failure(librdp_server_peer* peer, uint32_t failure_code)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_x224_build_negotiation_failure(&response, failure_code);
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_server_peer_send_all(peer, response.data, response.length);
        if (status == LIBRDP_STATUS_OK)
            rdp_server_metric_add(&peer->metrics.pdu_out, 1u);
    }
    rdp_buffer_free(&response);
    rdp_server_close_peer(peer, status == LIBRDP_STATUS_OK ? LIBRDP_SERVER_PEER_CLOSED
                                                           : LIBRDP_SERVER_PEER_FAILED);
    return status == LIBRDP_STATUS_OK ? LIBRDP_STATUS_UNSUPPORTED : status;
}

static int rdp_server_tls_material_available(const librdp_server_peer* peer)
{
    return peer && peer->tls_certificate_path && peer->tls_certificate_path[0] != '\0' &&
           peer->tls_private_key_path && peer->tls_private_key_path[0] != '\0';
}

static int rdp_server_nla_material_available(const librdp_server_peer* peer)
{
    return rdp_server_tls_material_available(peer) &&
           peer->nla_username && peer->nla_username[0] != '\0' &&
           peer->nla_password && peer->nla_password[0] != '\0';
}

static int rdp_server_uses_standard_security(const librdp_server_peer* peer)
{
    return peer && peer->selected_protocol == RDP_X224_PROTOCOL_STANDARD;
}

/*
 * Prepare per-peer Standard Security material before GCC Server Security Data
 * is serialized. The generated private key never leaves the peer, while the
 * public legacy certificate is advertised on the wire.
 */
static librdp_status rdp_server_prepare_standard_security(librdp_server_peer* peer)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_server_uses_standard_security(peer) || peer->standard_private_key)
        return LIBRDP_STATUS_OK;
    status = rdp_security_generate_client_random(peer->standard_server_random);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_generate_server_certificate(&peer->standard_private_key, &peer->standard_certificate);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.standard_security.material.ready",
                        "certificate_len=%u",
                        (unsigned)peer->standard_certificate.length);
    return status;
}

static librdp_status rdp_server_select_protocol(const librdp_server_peer* peer,
                                                const rdp_x224_connection_request* request,
                                                uint32_t* selected_protocol,
                                                uint32_t* failure_code)
{
    uint32_t requested = RDP_X224_PROTOCOL_STANDARD;
    int standard_requested = 0;

    if (!peer || !request || !selected_protocol || !failure_code)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    requested = request->negotiation.present ? request->requested_protocols : RDP_X224_PROTOCOL_STANDARD;
    standard_requested = !request->negotiation.present || requested == RDP_X224_PROTOCOL_STANDARD;
    *selected_protocol = RDP_X224_PROTOCOL_STANDARD;
    *failure_code = RDP_SERVER_NEGOTIATION_FAILURE_SSL_NOT_ALLOWED;
    if (peer->security_mode == LIBRDP_SECURITY_STANDARD)
    {
        if (standard_requested)
            return LIBRDP_STATUS_OK;
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    if (peer->security_mode == LIBRDP_SECURITY_TLS)
    {
        if (!rdp_server_tls_material_available(peer))
        {
            *failure_code = RDP_SERVER_NEGOTIATION_FAILURE_SSL_CERT_NOT_ON_SERVER;
            return LIBRDP_STATUS_UNSUPPORTED;
        }
        if ((requested & RDP_X224_PROTOCOL_TLS) != 0)
        {
            *selected_protocol = RDP_X224_PROTOCOL_TLS;
            return LIBRDP_STATUS_OK;
        }
        *failure_code = RDP_SERVER_NEGOTIATION_FAILURE_SSL_REQUIRED;
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    if (peer->security_mode == LIBRDP_SECURITY_NLA)
    {
        if (!rdp_server_tls_material_available(peer))
        {
            *failure_code = RDP_SERVER_NEGOTIATION_FAILURE_SSL_CERT_NOT_ON_SERVER;
            return LIBRDP_STATUS_UNSUPPORTED;
        }
        if (!rdp_server_nla_material_available(peer))
        {
            *failure_code = RDP_SERVER_NEGOTIATION_FAILURE_HYBRID_REQUIRED;
            return LIBRDP_STATUS_UNSUPPORTED;
        }
        if ((requested & RDP_X224_PROTOCOL_NLA) != 0)
        {
            *selected_protocol = RDP_X224_PROTOCOL_NLA;
            return LIBRDP_STATUS_OK;
        }
        *failure_code = RDP_SERVER_NEGOTIATION_FAILURE_HYBRID_REQUIRED;
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    if (rdp_server_nla_material_available(peer) && (requested & RDP_X224_PROTOCOL_NLA) != 0)
    {
        *selected_protocol = RDP_X224_PROTOCOL_NLA;
        return LIBRDP_STATUS_OK;
    }
    if (rdp_server_tls_material_available(peer) && (requested & RDP_X224_PROTOCOL_TLS) != 0)
    {
        *selected_protocol = RDP_X224_PROTOCOL_TLS;
        return LIBRDP_STATUS_OK;
    }
    if (standard_requested)
        return LIBRDP_STATUS_OK;
    return LIBRDP_STATUS_UNSUPPORTED;
}

/*
 * Read exactly one complete TPKT from the peer transport, regardless of
 * whether the byte source is the initial TCP socket or the TLS layer selected
 * after X.224 negotiation. The peer input buffer owns partial data between
 * calls, so malformed lengths must fail without discarding unrelated queued
 * bytes.
 */
static librdp_status rdp_server_read_tpkt(librdp_server_peer* peer,
                                          int timeout_ms,
                                          rdp_tpkt* packet,
                                          size_t* packet_len)
{
    struct pollfd pfd;
    uint8_t chunk[2048];
    ssize_t read_len = 0;
    int poll_result = 0;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t total = 0;

    if (!peer || !packet || !packet_len || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->fd < 0)
        return LIBRDP_STATUS_STATE;
    pfd.fd = peer->fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (peer->pending_revents != 0)
    {
        pfd.revents = peer->pending_revents;
        peer->pending_revents = 0;
        poll_result = 1;
    }
    else
    {
        poll_result = poll(&pfd, 1, timeout_ms);
        if (poll_result == 0)
            return LIBRDP_STATUS_TIMEOUT;
        if (poll_result < 0)
            return errno == EINTR ? LIBRDP_STATUS_TIMEOUT : LIBRDP_STATUS_IO_ERROR;
    }
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
    {
        rdp_server_set_state(peer, LIBRDP_SERVER_PEER_FAILED);
        return LIBRDP_STATUS_IO_ERROR;
    }
    if (peer->tls_active)
    {
        int tls_read = SSL_read(peer->tls, chunk, (int)sizeof(chunk));

        if (tls_read <= 0)
        {
            short wait_events = 0;
            librdp_status tls_status = rdp_server_tls_status(peer->tls, tls_read, &wait_events);

            (void)wait_events;
            if (tls_status == LIBRDP_STATUS_AGAIN)
                return LIBRDP_STATUS_TIMEOUT;
            if (tls_status == LIBRDP_STATUS_CLOSED)
                rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_CLOSED);
            return tls_status;
        }
        read_len = tls_read;
    }
    else
    {
        read_len = recv(peer->fd, chunk, sizeof(chunk), 0);
        if (read_len == 0)
        {
            rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_CLOSED);
            return LIBRDP_STATUS_CLOSED;
        }
        if (read_len < 0)
            return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? LIBRDP_STATUS_TIMEOUT
                                                                             : LIBRDP_STATUS_IO_ERROR;
    }
    rdp_server_metric_add(&peer->metrics.bytes_read, (uint64_t)read_len);
    if (peer->input.length + (size_t)read_len > RDP_SERVER_INITIAL_READ_MAX)
    {
        rdp_server_set_state(peer, LIBRDP_SERVER_PEER_FAILED);
        rdp_server_metric_add(&peer->metrics.limits_rejected, 1u);
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    status = rdp_buffer_append(&peer->input, chunk, (size_t)read_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (peer->input.length < 4u)
        return LIBRDP_STATUS_TIMEOUT;
    if (peer->input.data[0] != 3u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    total = ((size_t)peer->input.data[2] << 8) | (size_t)peer->input.data[3];
    if (total < 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (total > peer->input.length)
        return LIBRDP_STATUS_TIMEOUT;
    status = rdp_tpkt_parse(peer->input.data, total, packet);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_set_state(peer, LIBRDP_SERVER_PEER_FAILED);
        return status;
    }
    rdp_server_metric_add(&peer->metrics.pdu_in, 1u);
    *packet_len = total;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_start_tls(librdp_server_peer* peer, int timeout_ms)
{
    librdp_status status = LIBRDP_STATUS_OK;
    int rc = 0;

    if (!peer || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->tls_active)
        return LIBRDP_STATUS_OK;
    if (!rdp_server_tls_material_available(peer))
        return LIBRDP_STATUS_UNSUPPORTED;
    if (!peer->tls_context)
    {
        peer->tls_context = SSL_CTX_new(TLS_server_method());
        if (!peer->tls_context)
            return LIBRDP_STATUS_TLS_HANDSHAKE_FAILED;
        if (SSL_CTX_use_certificate_file(peer->tls_context, peer->tls_certificate_path, SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(peer->tls_context, peer->tls_private_key_path, SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(peer->tls_context) != 1)
        {
            SSL_CTX_free(peer->tls_context);
            peer->tls_context = NULL;
            ERR_clear_error();
            return LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED;
        }
    }
    if (!peer->tls)
    {
        peer->tls = SSL_new(peer->tls_context);
        if (!peer->tls)
            return LIBRDP_STATUS_TLS_HANDSHAKE_FAILED;
        if (SSL_set_fd(peer->tls, peer->fd) != 1)
            return LIBRDP_STATUS_TLS_HANDSHAKE_FAILED;
    }
    rc = SSL_accept(peer->tls);
    if (rc != 1)
    {
        short wait_events = 0;

        status = rdp_server_tls_status(peer->tls, rc, &wait_events);
        if (status == LIBRDP_STATUS_AGAIN)
        {
            status = rdp_server_wait_fd(peer->fd, wait_events, timeout_ms);
            return status == LIBRDP_STATUS_OK ? LIBRDP_STATUS_TIMEOUT : status;
        }
        ERR_clear_error();
        return status == LIBRDP_STATUS_CLOSED ? LIBRDP_STATUS_TLS_HANDSHAKE_FAILED : status;
    }
    peer->tls_active = 1;
    rdp_trace_event(RDP_TRACE_TRANSPORT,
                    "server.transport.tls.accept.done",
                    "version=%s cipher=%s",
                    SSL_get_version(peer->tls),
                    SSL_get_cipher(peer->tls));
    rdp_server_set_state(peer,
                         peer->selected_protocol == RDP_X224_PROTOCOL_NLA ?
                             LIBRDP_SERVER_PEER_NLA_AUTHENTICATING :
                             LIBRDP_SERVER_PEER_X224_CONFIRMED);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_append_utf16le_ascii(rdp_buffer* buffer, const char* text)
{
    if (!buffer || !text)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (const unsigned char* current = (const unsigned char*)text; *current; current++)
    {
        if (*current >= 0x80u)
            return LIBRDP_STATUS_UNSUPPORTED;
        librdp_status status = rdp_buffer_append_u16_le(buffer, (uint16_t)*current);

        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_credssp_packet_length(const rdp_buffer* input, size_t* total)
{
    uint8_t length_byte = 0;
    size_t header_len = 2u;
    size_t payload_len = 0;
    size_t length_len = 0;

    if (!input || !total)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (input->length < 2u)
        return LIBRDP_STATUS_TIMEOUT;
    if (input->data[0] != 0x30u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    length_byte = input->data[1];
    if ((length_byte & 0x80u) == 0)
    {
        payload_len = length_byte;
    }
    else
    {
        length_len = length_byte & 0x7fu;
        if (length_len == 0 || length_len > 4u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        header_len += length_len;
        if (input->length < header_len)
            return LIBRDP_STATUS_TIMEOUT;
        for (size_t i = 0; i < length_len; i++)
        {
            if (payload_len > (SIZE_MAX >> 8))
                return LIBRDP_STATUS_LIMIT_EXCEEDED;
            payload_len = (payload_len << 8) | input->data[2u + i];
        }
    }
    if (payload_len > RDP_SERVER_CREDSSP_MESSAGE_MAX || header_len > SIZE_MAX - payload_len)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    *total = header_len + payload_len;
    if (*total > RDP_SERVER_CREDSSP_MESSAGE_MAX)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    return input->length >= *total ? LIBRDP_STATUS_OK : LIBRDP_STATUS_TIMEOUT;
}

/*
 * Read one DER TSRequest from the TLS stream. CredSSP runs directly over TLS,
 * not inside TPKT, so partial DER bytes are buffered separately from the later
 * RDP packet parser while preserving strict maximum length enforcement.
 */
static librdp_status rdp_server_read_credssp_ts_request(librdp_server_peer* peer,
                                                        int timeout_ms,
                                                        rdp_buffer* packet)
{
    uint8_t chunk[2048];
    size_t total = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !packet || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!peer->tls_active || !peer->tls)
        return LIBRDP_STATUS_STATE;
    status = rdp_server_credssp_packet_length(&peer->input, &total);
    if (status == LIBRDP_STATUS_TIMEOUT)
    {
        struct pollfd pfd;
        int rc = 0;
        int tls_read = 0;

        pfd.fd = peer->fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        rc = poll(&pfd, 1, timeout_ms);
        if (rc == 0)
            return LIBRDP_STATUS_TIMEOUT;
        if (rc < 0)
            return errno == EINTR ? LIBRDP_STATUS_TIMEOUT : LIBRDP_STATUS_IO_ERROR;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
            return LIBRDP_STATUS_IO_ERROR;
        tls_read = SSL_read(peer->tls, chunk, (int)sizeof(chunk));
        if (tls_read <= 0)
        {
            short wait_events = 0;
            librdp_status tls_status = rdp_server_tls_status(peer->tls, tls_read, &wait_events);

            (void)wait_events;
            return tls_status == LIBRDP_STATUS_AGAIN ? LIBRDP_STATUS_TIMEOUT : tls_status;
        }
        rdp_server_metric_add(&peer->metrics.bytes_read, (uint64_t)tls_read);
        if (peer->input.length + (size_t)tls_read > RDP_SERVER_CREDSSP_MESSAGE_MAX)
        {
            rdp_server_metric_add(&peer->metrics.limits_rejected, 1u);
            return LIBRDP_STATUS_LIMIT_EXCEEDED;
        }
        status = rdp_buffer_append(&peer->input, chunk, (size_t)tls_read);
        if (status != LIBRDP_STATUS_OK)
            return status;
        status = rdp_server_credssp_packet_length(&peer->input, &total);
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(packet, peer->input.data, total);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_consume(&peer->input, total);
    if (status == LIBRDP_STATUS_OK)
        rdp_server_metric_add(&peer->metrics.pdu_in, 1u);
    return status;
}

static librdp_status rdp_server_send_credssp_ts_request(librdp_server_peer* peer,
                                                        uint32_t version,
                                                        const uint8_t* nego_token,
                                                        size_t nego_token_len,
                                                        const uint8_t* auth_info,
                                                        size_t auth_info_len,
                                                        const uint8_t* pub_key_auth,
                                                        size_t pub_key_auth_len)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&response);
    status = rdp_credssp_write_ts_request(&response,
                                          version ? version : 6u,
                                          nego_token,
                                          nego_token_len,
                                          auth_info,
                                          auth_info_len,
                                          pub_key_auth,
                                          pub_key_auth_len,
                                          NULL,
                                          0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_peer_send_all(peer, response.data, response.length);
    if (status == LIBRDP_STATUS_OK)
        rdp_server_metric_add(&peer->metrics.pdu_out, 1u);
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_server_prepare_credssp_challenge(librdp_server_peer* peer,
                                                          rdp_ntlm_challenge* challenge)
{
    static const uint8_t target_info_eol[] = {0, 0, 0, 0};
    const char* target_name = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !challenge)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    peer->credssp_target_name.length = 0;
    peer->credssp_target_info.length = 0;
    target_name = peer->server_name ? peer->server_name : "librdp";
    status = rdp_server_append_utf16le_ascii(&peer->credssp_target_name, target_name);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&peer->credssp_target_info, target_info_eol, sizeof(target_info_eol));
    if (status == LIBRDP_STATUS_OK && RAND_bytes(peer->credssp_server_challenge,
                                                 (int)sizeof(peer->credssp_server_challenge)) != 1)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status != LIBRDP_STATUS_OK)
        return status;
    memset(challenge, 0, sizeof(*challenge));
    challenge->flags = rdp_credssp_default_ntlm_challenge_flags();
    memcpy(challenge->server_challenge,
           peer->credssp_server_challenge,
           sizeof(peer->credssp_server_challenge));
    challenge->target_name = peer->credssp_target_name.data;
    challenge->target_name_len = peer->credssp_target_name.length;
    challenge->target_info = peer->credssp_target_info.data;
    challenge->target_info_len = peer->credssp_target_info.length;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_tls_public_key(librdp_server_peer* peer, rdp_buffer* public_key)
{
    X509* certificate = NULL;
    EVP_PKEY* key = NULL;
    unsigned char* cursor = NULL;
    int encoded_len = 0;
    int written = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !public_key || !peer->tls)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    certificate = SSL_get_certificate(peer->tls);
    if (!certificate)
        return LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED;
    key = X509_get_pubkey(certificate);
    if (!key)
        return LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED;
    encoded_len = i2d_PublicKey(key, NULL);
    if (encoded_len <= 0)
    {
        EVP_PKEY_free(key);
        return LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED;
    }
    status = rdp_buffer_reserve(public_key, (size_t)encoded_len);
    if (status == LIBRDP_STATUS_OK)
    {
        cursor = public_key->data;
        written = i2d_PublicKey(key, &cursor);
        if (written != encoded_len)
            status = LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED;
        else
            public_key->length = (size_t)written;
    }
    EVP_PKEY_free(key);
    return status;
}

static librdp_status rdp_server_handle_credssp_negotiate(librdp_server_peer* peer, int timeout_ms)
{
    rdp_buffer packet;
    rdp_buffer ntlm_challenge;
    rdp_buffer spnego_challenge;
    rdp_credssp_ts_request request;
    rdp_ntlm_negotiate negotiate;
    rdp_ntlm_challenge challenge;
    const uint8_t* ntlm = NULL;
    size_t ntlm_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&packet);
    rdp_buffer_init(&ntlm_challenge);
    rdp_buffer_init(&spnego_challenge);
    status = rdp_server_read_credssp_ts_request(peer, timeout_ms, &packet);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_parse_ts_request(packet.data, packet.length, &request);
    if (status == LIBRDP_STATUS_OK)
        status = request.client_nonce_len == sizeof(peer->credssp_client_nonce) ? LIBRDP_STATUS_OK
                                                                                : LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
    {
        memcpy(peer->credssp_client_nonce, request.client_nonce, sizeof(peer->credssp_client_nonce));
        peer->credssp_client_nonce_ready = 1;
        status = rdp_credssp_extract_ntlm_message(request.nego_token,
                                                  request.nego_token_len,
                                                  1,
                                                  &ntlm,
                                                  &ntlm_len);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_parse_ntlm_negotiate(ntlm, ntlm_len, &negotiate);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_prepare_credssp_challenge(peer, &challenge);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_write_ntlm_challenge(&ntlm_challenge, &challenge);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_write_spnego_ntlm_challenge(&spnego_challenge,
                                                         ntlm_challenge.data,
                                                         ntlm_challenge.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_credssp_ts_request(peer,
                                                    request.version,
                                                    spnego_challenge.data,
                                                    spnego_challenge.length,
                                                    NULL,
                                                    0,
                                                    NULL,
                                                    0);
    if (status == LIBRDP_STATUS_OK)
    {
        peer->credssp_stage = 1;
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.credssp.negotiate.done",
                        "flags=%u target_info_len=%u",
                        negotiate.flags,
                        (unsigned)challenge.target_info_len);
    }
    rdp_buffer_free(&spnego_challenge);
    rdp_buffer_free(&ntlm_challenge);
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status rdp_server_handle_credssp_authenticate(librdp_server_peer* peer, int timeout_ms)
{
    rdp_buffer packet;
    rdp_credssp_ts_request request;
    rdp_ntlm_challenge challenge;
    rdp_ntlm_authenticate_result result;
    const uint8_t* ntlm = NULL;
    size_t ntlm_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&packet);
    memset(&result, 0, sizeof(result));
    status = rdp_server_read_credssp_ts_request(peer, timeout_ms, &packet);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_parse_ts_request(packet.data, packet.length, &request);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_extract_ntlm_message(request.nego_token,
                                                  request.nego_token_len,
                                                  3,
                                                  &ntlm,
                                                  &ntlm_len);
    if (status == LIBRDP_STATUS_OK)
    {
        memset(&challenge, 0, sizeof(challenge));
        challenge.flags = rdp_credssp_default_ntlm_challenge_flags();
        memcpy(challenge.server_challenge,
               peer->credssp_server_challenge,
               sizeof(peer->credssp_server_challenge));
        challenge.target_name = peer->credssp_target_name.data;
        challenge.target_name_len = peer->credssp_target_name.length;
        challenge.target_info = peer->credssp_target_info.data;
        challenge.target_info_len = peer->credssp_target_info.length;
        status = rdp_credssp_verify_ntlm_authenticate(ntlm,
                                                      ntlm_len,
                                                      &challenge,
                                                      peer->nla_username,
                                                      peer->nla_password,
                                                      &result);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_ntlm_server_security_init(&peer->credssp_security, &result);
    if (status == LIBRDP_STATUS_OK)
    {
        peer->credssp_security_ready = 1;
        status = rdp_server_send_credssp_ts_request(peer, request.version, NULL, 0, NULL, 0, NULL, 0);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        peer->credssp_stage = 2;
        rdp_trace_event(RDP_TRACE_PROTOCOL, "server.credssp.authenticate.done", "username=redacted");
    }
    OPENSSL_cleanse(&result, sizeof(result));
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status rdp_server_handle_credssp_pubkey(librdp_server_peer* peer, int timeout_ms)
{
    rdp_buffer packet;
    rdp_buffer public_key;
    rdp_buffer pub_key_auth;
    rdp_credssp_ts_request request;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&packet);
    rdp_buffer_init(&public_key);
    rdp_buffer_init(&pub_key_auth);
    status = rdp_server_read_credssp_ts_request(peer, timeout_ms, &packet);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_parse_ts_request(packet.data, packet.length, &request);
    if (status == LIBRDP_STATUS_OK && !peer->credssp_security_ready)
        status = LIBRDP_STATUS_STATE;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_tls_public_key(peer, &public_key);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_verify_client_public_key_hash(&peer->credssp_security,
                                                           peer->credssp_client_nonce,
                                                           sizeof(peer->credssp_client_nonce),
                                                           public_key.data,
                                                           public_key.length,
                                                           request.pub_key_auth,
                                                           request.pub_key_auth_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_encrypt_server_public_key_hash(&peer->credssp_security,
                                                            peer->credssp_client_nonce,
                                                            sizeof(peer->credssp_client_nonce),
                                                            public_key.data,
                                                            public_key.length,
                                                            &pub_key_auth);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_credssp_ts_request(peer,
                                                    request.version,
                                                    NULL,
                                                    0,
                                                    NULL,
                                                    0,
                                                    pub_key_auth.data,
                                                    pub_key_auth.length);
    if (status == LIBRDP_STATUS_OK)
    {
        peer->credssp_stage = 3;
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.credssp.pubkey.done",
                        "public_key_len=%u",
                        (unsigned)public_key.length);
    }
    rdp_buffer_free(&pub_key_auth);
    rdp_buffer_free(&public_key);
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status rdp_server_handle_credssp_credentials(librdp_server_peer* peer, int timeout_ms)
{
    rdp_buffer packet;
    rdp_credssp_ts_request request;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&packet);
    status = rdp_server_read_credssp_ts_request(peer, timeout_ms, &packet);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_parse_ts_request(packet.data, packet.length, &request);
    if (status == LIBRDP_STATUS_OK && !peer->credssp_security_ready)
        status = LIBRDP_STATUS_STATE;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_decrypt_password_credentials(&peer->credssp_security,
                                                          request.auth_info,
                                                          request.auth_info_len);
    if (status == LIBRDP_STATUS_OK)
    {
        peer->nla_authenticated = 1;
        peer->credssp_stage = 4;
        rdp_server_set_state(peer, LIBRDP_SERVER_PEER_X224_CONFIRMED);
        rdp_trace_event(RDP_TRACE_PROTOCOL, "server.credssp.done", "credentials=redacted");
    }
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status rdp_server_handle_credssp(librdp_server_peer* peer, int timeout_ms)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_server_nla_material_available(peer))
        return LIBRDP_STATUS_UNSUPPORTED;
    if (peer->credssp_stage == 0)
        return rdp_server_handle_credssp_negotiate(peer, timeout_ms);
    if (peer->credssp_stage == 1)
        return rdp_server_handle_credssp_authenticate(peer, timeout_ms);
    if (peer->credssp_stage == 2)
        return rdp_server_handle_credssp_pubkey(peer, timeout_ms);
    if (peer->credssp_stage == 3)
        return rdp_server_handle_credssp_credentials(peer, timeout_ms);
    return LIBRDP_STATUS_STATE;
}

static librdp_status rdp_server_handle_x224(librdp_server_peer* peer, const rdp_tpkt* packet)
{
    rdp_x224_connection_request request;
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t selected_protocol = RDP_X224_PROTOCOL_STANDARD;
    uint32_t failure_code = RDP_SERVER_NEGOTIATION_FAILURE_SSL_NOT_ALLOWED;

    status = rdp_x224_parse_connection_request(packet->payload, packet->payload_len, &request);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_set_state(peer, LIBRDP_SERVER_PEER_FAILED);
        return status;
    }
    status = rdp_server_select_protocol(peer, &request, &selected_protocol, &failure_code);
    if (status != LIBRDP_STATUS_OK)
        return rdp_server_send_x224_failure(peer, failure_code);

    rdp_buffer_init(&response);
    status = rdp_x224_build_connection_confirm_ex(&response,
                                                  selected_protocol,
                                                  request.negotiation.present);
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_server_peer_send_all(peer, response.data, response.length);
        if (status == LIBRDP_STATUS_OK)
            rdp_server_metric_add(&peer->metrics.pdu_out, 1u);
    }
    rdp_buffer_free(&response);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        return status;
    }
    peer->selected_protocol = selected_protocol;
    rdp_server_set_state(peer,
                         (selected_protocol == RDP_X224_PROTOCOL_TLS ||
                          selected_protocol == RDP_X224_PROTOCOL_NLA) ?
                             LIBRDP_SERVER_PEER_TLS_HANDSHAKING :
                             LIBRDP_SERVER_PEER_X224_CONFIRMED);
    return LIBRDP_STATUS_OK;
}

/*
 * Validate MCS Connect-Initial, capture client channel declarations, and emit
 * GCC/MCS response data. Standard Security material is generated here because
 * SC_SECURITY must carry the peer-specific random and certificate.
 */
static librdp_status rdp_server_handle_mcs_connect_initial(librdp_server_peer* peer, const rdp_tpkt* packet)
{
    const uint8_t* x224_data = NULL;
    size_t x224_data_len = 0;
    rdp_mcs_connect_initial mcs_initial;
    rdp_gcc_conference_request gcc_request;
    rdp_gcc_client_data_summary client_data;
    rdp_gcc_server_config server_config;
    rdp_buffer server_blocks;
    rdp_buffer gcc_response;
    rdp_buffer mcs_response;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&server_blocks);
    rdp_buffer_init(&gcc_response);
    rdp_buffer_init(&mcs_response);
    memset(&server_config, 0, sizeof(server_config));
    status = rdp_x224_parse_data(packet->payload, packet->payload_len, &x224_data, &x224_data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_parse_connect_initial(x224_data, x224_data_len, &mcs_initial);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_parse_conference_create_request(mcs_initial.user_data,
                                                         mcs_initial.user_data_len,
                                                         &gcc_request);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_parse_client_data_blocks(gcc_request.user_data,
                                                  gcc_request.user_data_len,
                                                  &client_data);
    if (status == LIBRDP_STATUS_OK && (!client_data.has_core || !client_data.has_security || !client_data.has_network))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
    {
        peer->width = client_data.desktop_width ? client_data.desktop_width : peer->width;
        peer->height = client_data.desktop_height ? client_data.desktop_height : peer->height;
        peer->advertised_channel_count = client_data.channel_count;
        rdp_server_dynamic_channels_reset(peer);
        memset(peer->advertised_channels, 0, sizeof(peer->advertised_channels));
        memset(peer->advertised_channel_ids, 0, sizeof(peer->advertised_channel_ids));
        memset(peer->advertised_channel_joined, 0, sizeof(peer->advertised_channel_joined));
        for (uint16_t channel_index = 0; channel_index < client_data.channel_count; channel_index++)
        {
            peer->advertised_channels[channel_index] = client_data.channels[channel_index];
            peer->advertised_channel_ids[channel_index] =
                (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 1u + channel_index);
            if (memcmp(client_data.channels[channel_index].name, "drdynvc", 7u) == 0 &&
                client_data.channels[channel_index].name[7] == '\0')
                peer->dynamic_channel_static_index = channel_index;
        }
        server_config.version = client_data.version ? client_data.version : RDP_GCC_CLIENT_VERSION_5;
        server_config.selected_protocol = peer->selected_protocol;
        server_config.early_capability_flags = client_data.early_capability_flags;
        server_config.mcs_channel_id = (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID;
        server_config.channel_count = client_data.channel_count;
        peer->multitransport_negotiated = 0;
        peer->multitransport_udp_active = 0;
        peer->multitransport_udp2_active = 0;
        peer->multitransport_flags = 0;
        if (client_data.has_multitransport &&
            (peer->requested_features & (uint32_t)LIBRDP_FEATURE_MULTITRANSPORT) != 0 &&
            (peer->requested_features &
             ((uint32_t)LIBRDP_FEATURE_UDP_TRANSPORT | (uint32_t)LIBRDP_FEATURE_UDP2_TRANSPORT)) != 0)
        {
            uint32_t flags = client_data.multitransport_flags & RDP_GCC_MULTITRANSPORT_SERVER_KNOWN_FLAGS;

            if ((flags & (RDP_GCC_MULTITRANSPORT_UDP_FECR | RDP_GCC_MULTITRANSPORT_UDP_FECL)) ==
                (RDP_GCC_MULTITRANSPORT_UDP_FECR | RDP_GCC_MULTITRANSPORT_UDP_FECL))
            {
                server_config.enable_multitransport = 1;
                server_config.multitransport_flags =
                    flags | RDP_GCC_MULTITRANSPORT_SOFTSYNC_TCP_TO_UDP;
                peer->multitransport_negotiated = 1;
                peer->multitransport_flags = server_config.multitransport_flags;
            }
        }
        if (rdp_server_uses_standard_security(peer))
        {
            status = rdp_server_prepare_standard_security(peer);
            if (status == LIBRDP_STATUS_OK)
            {
                server_config.encryption_method = RDP_SECURITY_METHOD_128BIT;
                server_config.encryption_level = RDP_SERVER_STANDARD_ENCRYPTION_LEVEL;
                server_config.server_random = peer->standard_server_random;
                server_config.server_random_len = RDP_SECURITY_CLIENT_RANDOM_LEN;
                server_config.server_certificate = peer->standard_certificate.data;
                server_config.server_certificate_len = (uint32_t)peer->standard_certificate.length;
            }
        }
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_write_server_data_blocks(&server_blocks, &server_config);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gcc_write_conference_create_response(&gcc_response, server_blocks.data, server_blocks.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_connect_response(&mcs_response, gcc_response.data, gcc_response.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_mcs_pdu(peer, &mcs_response);
    rdp_buffer_free(&mcs_response);
    rdp_buffer_free(&gcc_response);
    rdp_buffer_free(&server_blocks);

    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        return status;
    }
    rdp_server_set_state(peer, LIBRDP_SERVER_PEER_MCS_CONNECTED);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_parse_x224_data_packet(const rdp_tpkt* packet, const uint8_t** data, size_t* data_len)
{
    if (!packet || !data || !data_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_x224_parse_data(packet->payload, packet->payload_len, data, data_len);
}

static librdp_status rdp_server_handle_erect_domain(librdp_server_peer* peer, const rdp_tpkt* packet)
{
    const uint8_t* data = NULL;
    size_t data_len = 0;
    librdp_status status = rdp_server_parse_x224_data_packet(packet, &data, &data_len);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_parse_erect_domain_request(data, data_len);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        return status;
    }
    rdp_server_set_state(peer, LIBRDP_SERVER_PEER_DOMAIN_READY);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_handle_attach_user(librdp_server_peer* peer, const rdp_tpkt* packet)
{
    const uint8_t* data = NULL;
    size_t data_len = 0;
    rdp_buffer confirm;
    librdp_status status = rdp_server_parse_x224_data_packet(packet, &data, &data_len);

    rdp_buffer_init(&confirm);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_parse_attach_user_request(data, data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_attach_user_confirm(&confirm, peer->user_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_mcs_pdu(peer, &confirm);
    rdp_buffer_free(&confirm);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        return status;
    }
    rdp_server_set_state(peer, LIBRDP_SERVER_PEER_USER_ATTACHED);
    return LIBRDP_STATUS_OK;
}

static int rdp_server_channel_allowed(const librdp_server_peer* peer, uint16_t channel_id)
{
    uint16_t first_static = (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 1u);
    uint16_t last_static = (uint16_t)(first_static + peer->advertised_channel_count);

    if (!peer)
        return 0;
    if (channel_id == peer->user_id || channel_id == RDP_MCS_GLOBAL_CHANNEL_ID)
        return 1;
    return channel_id >= first_static && channel_id < last_static;
}

static int rdp_server_static_channel_index(const librdp_server_peer* peer, uint16_t channel_id, uint16_t* index)
{
    uint16_t first_static = (uint16_t)(RDP_MCS_GLOBAL_CHANNEL_ID + 1u);

    if (!peer || channel_id < first_static)
        return 0;
    if ((uint32_t)(channel_id - first_static) >= peer->advertised_channel_count)
        return 0;
    if (index)
        *index = (uint16_t)(channel_id - first_static);
    return 1;
}

static librdp_status rdp_server_send_demand_active(librdp_server_peer* peer)
{
    rdp_buffer demand;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&demand);
    status = rdp_slowpath_write_demand_active(&demand,
                                              peer->share_id,
                                              (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                              peer->width,
                                              peer->height,
                                              peer->server_name ? peer->server_name : "librdp-server");
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_slowpath(peer, &demand);
    rdp_buffer_free(&demand);
    if (status == LIBRDP_STATUS_OK)
        rdp_server_set_state(peer, LIBRDP_SERVER_PEER_ACTIVATING);
    return status;
}

/*
 * Complete the permissive server-side licensing path used by the current
 * Standard RDP server runtime. The alert is sent before Demand Active so real
 * clients leave their licensing state machine before activation parsing.
 */
static librdp_status rdp_server_send_valid_client_license(librdp_server_peer* peer)
{
    rdp_buffer license;
    rdp_buffer security_payload;
    rdp_buffer mcs;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&license);
    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&mcs);
    status = rdp_license_write_error_alert(&license,
                                           RDP_LICENSE_VERSION_3,
                                           RDP_LICENSE_ERROR_STATUS_VALID_CLIENT,
                                           RDP_LICENSE_STATE_TRANSITION_NO_TRANSITION,
                                           RDP_LICENSE_BLOB_ERROR,
                                           NULL,
                                           0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_header(&security_payload,
                                           (uint16_t)(RDP_SEC_LICENSE_PKT | RDP_SEC_LICENSE_ENCRYPT_SC));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&security_payload, license.data, license.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_send_data_indication(&mcs,
                                                    peer->user_id,
                                                    (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                    security_payload.data,
                                                    security_payload.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_mcs_pdu(peer, &mcs);
    rdp_buffer_free(&mcs);
    rdp_buffer_free(&security_payload);
    rdp_buffer_free(&license);
    if (status == LIBRDP_STATUS_OK)
    {
        peer->licensing_done = 1;
        rdp_server_set_state(peer, LIBRDP_SERVER_PEER_LICENSING);
    }
    return status;
}

static int rdp_server_security_payload_has_flag(const uint8_t* input, size_t input_len, uint16_t required);
static librdp_status rdp_server_handle_security_exchange(librdp_server_peer* peer,
                                                         const uint8_t* input,
                                                         size_t input_len);
static librdp_status rdp_server_parse_client_info_security_payload(librdp_server_peer* peer,
                                                                   const uint8_t* input,
                                                                   size_t input_len,
                                                                   rdp_client_info_summary* summary);

static size_t rdp_server_channel_name_len(const char name[8])
{
    size_t length = 0;

    while (length < 8u && name[length] != '\0')
        length++;
    return length;
}

static void rdp_server_copy_channel_name(char output[LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY], const char name[8])
{
    size_t length = rdp_server_channel_name_len(name);

    memset(output, 0, LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY);
    if (length > 0)
        memcpy(output, name, length);
}

static uint16_t rdp_server_dynamic_static_channel_id(const librdp_server_peer* peer)
{
    if (!peer || peer->dynamic_channel_static_index >= peer->advertised_channel_count)
        return 0;
    return peer->advertised_channel_ids[peer->dynamic_channel_static_index];
}

static rdp_server_dynamic_channel* rdp_server_find_dynamic_channel(librdp_server_peer* peer, uint32_t channel_id)
{
    if (!peer)
        return NULL;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_DYNAMIC_CHANNELS; i++)
    {
        if (peer->dynamic_channels[i].open && peer->dynamic_channels[i].channel_id == channel_id)
            return &peer->dynamic_channels[i];
    }
    return NULL;
}

static rdp_server_dynamic_channel* rdp_server_find_dynamic_channel_any(librdp_server_peer* peer, uint32_t channel_id)
{
    if (!peer)
        return NULL;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_DYNAMIC_CHANNELS; i++)
    {
        rdp_server_dynamic_channel* channel = &peer->dynamic_channels[i];

        if ((channel->open || channel->pending_open) && channel->channel_id == channel_id)
            return channel;
    }
    return NULL;
}

static rdp_server_dynamic_channel* rdp_server_find_pending_dynamic_channel(librdp_server_peer* peer,
                                                                           uint32_t channel_id)
{
    rdp_server_dynamic_channel* channel = rdp_server_find_dynamic_channel_any(peer, channel_id);

    return channel && channel->pending_open ? channel : NULL;
}

static rdp_server_dynamic_channel* rdp_server_allocate_dynamic_channel(librdp_server_peer* peer)
{
    if (!peer)
        return NULL;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_DYNAMIC_CHANNELS; i++)
    {
        if (!peer->dynamic_channels[i].open && !peer->dynamic_channels[i].pending_open)
            return &peer->dynamic_channels[i];
    }
    return NULL;
}

static int rdp_server_dynamic_channel_name_valid(const char* name, size_t* name_len)
{
    size_t length = 0;

    if (!name)
        return 0;
    while (name[length] != '\0')
    {
        unsigned char ch = (unsigned char)name[length];

        if (length >= RDP_SERVER_DYNAMIC_CHANNEL_NAME_CAPACITY - 1u || ch < 0x21u || ch > 0x7eu)
            return 0;
        length++;
    }
    if (length == 0)
        return 0;
    if (name_len)
        *name_len = length;
    return 1;
}

static void rdp_server_emit_dynamic_channel_event(librdp_server_peer* peer,
                                                  const rdp_server_dynamic_channel* channel,
                                                  librdp_server_channel_event_type type,
                                                  const uint8_t* data,
                                                  size_t data_len)
{
    librdp_server_channel_event event;

    if (!peer || !channel || !peer->channel_callback)
        return;
    memset(&event, 0, sizeof(event));
    event.version = LIBRDP_SERVER_CHANNEL_EVENT_VERSION;
    event.size = (uint32_t)sizeof(event);
    event.type = type;
    event.channel_id = rdp_server_dynamic_static_channel_id(peer);
    event.dynamic_channel_id = channel->channel_id;
    event.dynamic_priority = channel->priority;
    event.name = channel->name;
    event.name_len = strlen(channel->name);
    event.data = data;
    event.data_len = data_len;
    peer->channel_callback(peer, &event, peer->channel_callback_user_data);
}

static void rdp_server_emit_input(librdp_server_peer* peer, const librdp_server_input_event* event)
{
    if (peer && event)
        rdp_server_metric_add(&peer->metrics.input_events, 1u);
    if (peer && peer->input_callback)
        peer->input_callback(peer, event, peer->input_callback_user_data);
}

static librdp_status rdp_server_send_activation_responses(librdp_server_peer* peer)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_slowpath_write_server_synchronize(&response,
                                                   peer->share_id,
                                                   (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                   peer->user_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_slowpath(peer, &response);
    response.length = 0;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_server_control(&response,
                                                   peer->share_id,
                                                   (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                   4);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_slowpath(peer, &response);
    response.length = 0;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_server_control(&response,
                                                   peer->share_id,
                                                   (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                   2);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_slowpath(peer, &response);
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_server_send_font_map(librdp_server_peer* peer)
{
    rdp_buffer font_map;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&font_map);
    status = rdp_slowpath_write_server_font_map(&font_map,
                                                peer->share_id,
                                                (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_slowpath(peer, &font_map);
    rdp_buffer_free(&font_map);
    return status;
}

static librdp_status rdp_server_handle_input_events(librdp_server_peer* peer,
                                                    const uint8_t* payload,
                                                    size_t payload_len)
{
    rdp_stream stream;
    uint16_t event_count = 0;
    uint16_t pad = 0;

    if (!peer || !payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_stream_init(&stream, payload, payload_len);
    if (rdp_stream_read_u16_le(&stream, &event_count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &pad) != LIBRDP_STATUS_OK ||
        event_count > 256u ||
        pad != 0 ||
        rdp_stream_remaining(&stream) != (size_t)event_count * 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (uint16_t i = 0; i < event_count; i++)
    {
        librdp_server_input_event event;
        uint16_t message_type = 0;

        if (librdp_server_input_event_init(&event) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u32_le(&stream, &event.event_time) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &message_type) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &event.flags) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &event.param1) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &event.param2) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (message_type == 0x0004u)
            event.type = LIBRDP_SERVER_INPUT_SCANCODE_KEY;
        else if (message_type == 0x0005u)
            event.type = LIBRDP_SERVER_INPUT_UNICODE_KEY;
        else if (message_type == 0x8001u)
        {
            event.type = LIBRDP_SERVER_INPUT_MOUSE;
            event.x = event.param1;
            event.y = event.param2;
        }
        else if (message_type == 0x8002u)
        {
            event.type = LIBRDP_SERVER_INPUT_EXTENDED_MOUSE;
            event.x = event.param1;
            event.y = event.param2;
        }
        else
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        rdp_server_emit_input(peer, &event);
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_handle_refresh_rect(librdp_server_peer* peer,
                                                    const uint8_t* payload,
                                                    size_t payload_len);

static librdp_status rdp_server_handle_suppress_output(librdp_server_peer* peer,
                                                       const uint8_t* payload,
                                                       size_t payload_len)
{
    librdp_server_input_event event;

    if (!peer || !payload || (payload_len != 4u && payload_len != 12u))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (librdp_server_input_event_init(&event) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    event.type = LIBRDP_SERVER_INPUT_SUPPRESS_OUTPUT;
    event.flags = payload[0] != 0 ? 1u : 0u;
    peer->updates_suppressed = (uint8_t)(event.flags ? 0u : 1u);
    if (payload_len == 12u)
    {
        uint16_t right = 0;
        uint16_t bottom = 0;

        event.x = (uint16_t)((uint16_t)payload[4] | ((uint16_t)payload[5] << 8));
        event.y = (uint16_t)((uint16_t)payload[6] | ((uint16_t)payload[7] << 8));
        right = (uint16_t)((uint16_t)payload[8] | ((uint16_t)payload[9] << 8));
        bottom = (uint16_t)((uint16_t)payload[10] | ((uint16_t)payload[11] << 8));
        if (right < event.x || bottom < event.y)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        event.width = (uint16_t)(right - event.x + 1u);
        event.height = (uint16_t)(bottom - event.y + 1u);
    }
    rdp_server_emit_input(peer, &event);
    return LIBRDP_STATUS_OK;
}

static int rdp_server_rect_valid(const librdp_server_peer* peer,
                                 uint32_t x,
                                 uint32_t y,
                                 uint32_t width,
                                 uint32_t height)
{
    if (!peer || width == 0 || height == 0)
        return 0;
    if (x >= peer->width || y >= peer->height)
        return 0;
    if (width > (uint32_t)peer->width - x || height > (uint32_t)peer->height - y)
        return 0;
    return 1;
}

static librdp_status rdp_server_surface_allocate(librdp_server_peer* peer, uint32_t width, uint32_t height)
{
    uint8_t* pixels = NULL;
    size_t stride = 0;
    size_t total = 0;

    if (!peer || width == 0 || height == 0 ||
        width > RDP_SERVER_MAX_DESKTOP_SIZE ||
        height > RDP_SERVER_MAX_DESKTOP_SIZE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    stride = width * 4u;
    if (height > SIZE_MAX / stride)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    total = stride * height;
    pixels = (uint8_t*)calloc(1u, total);
    if (!pixels)
        return LIBRDP_STATUS_NO_MEMORY;
    free(peer->framebuffer);
    peer->framebuffer = pixels;
    peer->framebuffer_len = total;
    peer->framebuffer_stride = stride;
    peer->width = (uint16_t)width;
    peer->height = (uint16_t)height;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_surface_ensure(librdp_server_peer* peer)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->framebuffer)
        return LIBRDP_STATUS_OK;
    return rdp_server_surface_allocate(peer, peer->width, peer->height);
}

/*
 * Serialize one already-bounded BGRA tile as an uncompressed slow-path bitmap
 * update. The caller owns tiling and MCS payload sizing; this helper validates
 * 16-bit wire coordinates, copies rows bottom-up as required by bitmap updates,
 * and fails without partially mutating peer state when any nested writer rejects
 * the tile.
 */
static librdp_status rdp_server_present_tile(librdp_server_peer* peer,
                                             uint32_t x,
                                             uint32_t y,
                                             uint32_t width,
                                             uint32_t height)
{
    rdp_buffer raw;
    rdp_buffer update;
    rdp_bitmap_rect rect;
    size_t dst_stride = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&raw);
    rdp_buffer_init(&update);
    if (!rdp_server_rect_valid(peer, x, y, width, height) ||
        width > 0xffffu ||
        height > 0xffffu ||
        x + width - 1u > 0xffffu ||
        y + height - 1u > 0xffffu)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.surface.tile.invalid",
                        "x=%u y=%u width=%u height=%u peer_width=%u peer_height=%u",
                        x,
                        y,
                        width,
                        height,
                        peer ? peer->width : 0,
                        peer ? peer->height : 0);
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
        goto out;
    }
    dst_stride = width * 4u;
    if (height > SIZE_MAX / dst_stride)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.surface.tile.overflow",
                        "width=%u height=%u stride=%u",
                        width,
                        height,
                        (unsigned)dst_stride);
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
        goto out;
    }
    status = rdp_buffer_reserve(&raw, dst_stride * height);
    if (status != LIBRDP_STATUS_OK)
        goto out;
    raw.length = dst_stride * height;
    for (uint32_t row = 0; row < height; row++)
    {
        const uint8_t* src = peer->framebuffer +
                             ((size_t)(y + height - 1u - row) * peer->framebuffer_stride) +
                             ((size_t)x * 4u);
        uint8_t* dst = raw.data + ((size_t)row * dst_stride);

        memcpy(dst, src, dst_stride);
    }
    memset(&rect, 0, sizeof(rect));
    rect.dest_left = (uint16_t)x;
    rect.dest_top = (uint16_t)y;
    rect.dest_right = (uint16_t)(x + width - 1u);
    rect.dest_bottom = (uint16_t)(y + height - 1u);
    rect.width = (uint16_t)width;
    rect.height = (uint16_t)height;
    rect.bits_per_pixel = 32;
    rect.flags = 0;
    rect.data = raw.data;
    rect.data_len = (uint32_t)raw.length;
    status = rdp_bitmap_write_update(&update, &rect, 1);
    if (status != LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.surface.tile.bitmap_failed",
                        "status=%s x=%u y=%u width=%u height=%u raw_len=%u",
                        librdp_status_name(status),
                        x,
                        y,
                        width,
                        height,
                        (unsigned)raw.length);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_buffer slowpath;

        rdp_buffer_init(&slowpath);
        status = rdp_slowpath_write_data_pdu(&slowpath,
                                             peer->share_id,
                                             (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                             RDP_SLOWPATH_DATA_PDU_UPDATE,
                                             update.data,
                                             update.length);
        if (status != LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "server.surface.tile.slowpath_failed",
                            "status=%s x=%u y=%u width=%u height=%u update_len=%u",
                            librdp_status_name(status),
                            x,
                            y,
                            width,
                            height,
                            (unsigned)update.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_send_slowpath(peer, &slowpath);
        if (status != LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "server.surface.tile.send_failed",
                            "status=%s x=%u y=%u width=%u height=%u slowpath_len=%u",
                            librdp_status_name(status),
                            x,
                            y,
                            width,
                            height,
                            (unsigned)slowpath.length);
        rdp_buffer_free(&slowpath);
    }

out:
    rdp_buffer_free(&update);
    rdp_buffer_free(&raw);
    return status;
}

/*
 * Present a dirty rectangle by splitting it into MCS-sized bitmap tiles. The
 * limiting budget is the T.125 SendDataIndication payload size, so the tile
 * planner accounts for bitmap-update and slow-path headers before choosing
 * horizontal and vertical chunks. Any failed tile aborts the presentation and
 * leaves the stored framebuffer intact for a later retry.
 */
static librdp_status rdp_server_surface_present_rect(librdp_server_peer* peer,
                                                     uint32_t x,
                                                     uint32_t y,
                                                     uint32_t width,
                                                     uint32_t height)
{
    const size_t max_mcs_payload = 0x7fffu;
    const size_t bitmap_update_overhead = 22u;
    const size_t slowpath_data_overhead = 18u;
    size_t max_raw_tile = 0;
    uint32_t max_tile_width = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE || peer->updates_suppressed)
        return LIBRDP_STATUS_STATE;
    status = rdp_server_surface_ensure(peer);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!rdp_server_rect_valid(peer, x, y, width, height))
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.surface.present.invalid",
                        "x=%u y=%u width=%u height=%u peer_width=%u peer_height=%u",
                        x,
                        y,
                        width,
                        height,
                        peer->width,
                        peer->height);
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    if (max_mcs_payload <= bitmap_update_overhead + slowpath_data_overhead)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    max_raw_tile = max_mcs_payload - bitmap_update_overhead - slowpath_data_overhead;
    max_tile_width = (uint32_t)(max_raw_tile / 4u);
    if (max_tile_width == 0 || width > UINT32_MAX - x || height > UINT32_MAX - y)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                          RDP_TRACE_LEVEL_DEBUG,
                          "server.surface.present.start",
                          "x=%u y=%u width=%u height=%u max_tile_width=%u peer_width=%u peer_height=%u",
                          x,
                          y,
                          width,
                          height,
                          max_tile_width,
                          peer->width,
                          peer->height);
    for (uint32_t column = 0; column < width; column += max_tile_width)
    {
        uint32_t tile_width = width - column;
        uint32_t rows_per_tile = 0;

        if (tile_width > max_tile_width)
            tile_width = max_tile_width;
        rows_per_tile = (uint32_t)(max_raw_tile / ((size_t)tile_width * 4u));
        if (rows_per_tile == 0)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        for (uint32_t row = 0; row < height; row += rows_per_tile)
        {
            uint32_t tile_height = height - row;

            if (tile_height > rows_per_tile)
                tile_height = rows_per_tile;
            status = rdp_server_present_tile(peer, x + column, y + row, tile_width, tile_height);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "server.surface.present.failed",
                                "status=%s column=%u row=%u tile_width=%u tile_height=%u",
                                librdp_status_name(status),
                                column,
                                row,
                                tile_width,
                                tile_height);
                return status;
            }
        }
    }
    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                          RDP_TRACE_LEVEL_DEBUG,
                          "server.surface.present.done",
                          "x=%u y=%u width=%u height=%u",
                          x,
                          y,
                          width,
                          height);
    rdp_server_metric_add(&peer->metrics.surface_updates, 1u);
    rdp_server_emit_surface_event(peer, x, y, width, height);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_handle_refresh_rect(librdp_server_peer* peer,
                                                    const uint8_t* payload,
                                                    size_t payload_len)
{
    rdp_stream stream;
    uint16_t count = 0;
    uint16_t pad = 0;

    if (!peer || !payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_stream_init(&stream, payload, payload_len);
    if (rdp_stream_read_u16_le(&stream, &count) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &pad) != LIBRDP_STATUS_OK ||
        count > 64u ||
        pad != 0 ||
        rdp_stream_remaining(&stream) != (size_t)count * 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (uint16_t i = 0; i < count; i++)
    {
        librdp_server_input_event event;
        uint16_t left = 0;
        uint16_t top = 0;
        uint16_t right = 0;
        uint16_t bottom = 0;
        librdp_status status = LIBRDP_STATUS_OK;

        if (librdp_server_input_event_init(&event) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &left) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &top) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &right) != LIBRDP_STATUS_OK ||
            rdp_stream_read_u16_le(&stream, &bottom) != LIBRDP_STATUS_OK ||
            right < left ||
            bottom < top)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        event.type = LIBRDP_SERVER_INPUT_REFRESH_RECT;
        event.x = left;
        event.y = top;
        event.width = (uint16_t)(right - left + 1u);
        event.height = (uint16_t)(bottom - top + 1u);
        rdp_server_emit_input(peer, &event);
        if (peer->framebuffer && !peer->updates_suppressed &&
            rdp_server_rect_valid(peer, event.x, event.y, event.width, event.height))
        {
            status = rdp_server_surface_present_rect(peer, event.x, event.y, event.width, event.height);
            if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_STATE)
                return status;
        }
    }
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_set_input_callback(librdp_server_peer* peer,
                                                    librdp_server_input_callback callback,
                                                    void* user_data)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    peer->input_callback = callback;
    peer->input_callback_user_data = user_data;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_set_channel_callback(librdp_server_peer* peer,
                                                      librdp_server_channel_callback callback,
                                                      void* user_data)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    peer->channel_callback = callback;
    peer->channel_callback_user_data = user_data;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_set_extension_callback(librdp_server_peer* peer,
                                                        librdp_server_extension_callback callback,
                                                        void* user_data)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    peer->extension_callback = callback;
    peer->extension_callback_user_data = user_data;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_set_event_callback(librdp_server_peer* peer,
                                                    librdp_server_event_callback callback,
                                                    void* user_data)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    peer->event_callback = callback;
    peer->event_callback_user_data = user_data;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_enable_feature_provider(librdp_server_peer* peer,
                                                         librdp_feature feature,
                                                         int enabled)
{
    if (!peer || !rdp_server_valid_feature_mask(feature))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_server_feature_provider_mask_valid(feature))
        return LIBRDP_STATUS_UNSUPPORTED;
    if (peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    if (enabled)
        peer->backend_features |= (uint32_t)feature;
    else
        peer->backend_features &= ~(uint32_t)feature;
    return LIBRDP_STATUS_OK;
}

uint32_t librdp_server_peer_static_channel_count(const librdp_server_peer* peer)
{
    return peer ? peer->advertised_channel_count : 0;
}

librdp_status librdp_server_peer_static_channel_at(const librdp_server_peer* peer,
                                                   uint32_t index,
                                                   librdp_server_static_channel_info* info)
{
    uint16_t channel_index = 0;

    if (!peer || !info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (index >= peer->advertised_channel_count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (librdp_server_static_channel_info_init(info) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    channel_index = (uint16_t)index;
    info->channel_id = peer->advertised_channel_ids[channel_index];
    info->flags = peer->advertised_channels[channel_index].flags;
    info->joined = peer->advertised_channel_joined[channel_index] != 0;
    rdp_server_copy_channel_name(info->name, peer->advertised_channels[channel_index].name);
    return LIBRDP_STATUS_OK;
}

uint32_t librdp_server_peer_dynamic_channel_count(const librdp_server_peer* peer)
{
    return peer ? peer->dynamic_channel_count : 0;
}

librdp_status librdp_server_peer_dynamic_channel_at(const librdp_server_peer* peer,
                                                    uint32_t index,
                                                    librdp_server_dynamic_channel_info* info)
{
    uint32_t seen = 0;

    if (!peer || !info)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (librdp_server_dynamic_channel_info_init(info) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_DYNAMIC_CHANNELS; i++)
    {
        const rdp_server_dynamic_channel* channel = &peer->dynamic_channels[i];

        if (!channel->open)
            continue;
        if (seen == index)
        {
            info->channel_id = channel->channel_id;
            info->priority = channel->priority;
            info->open = 1;
            rdp_server_copy_token(info->name, sizeof(info->name), channel->name);
            return LIBRDP_STATUS_OK;
        }
        seen++;
    }
    return LIBRDP_STATUS_INVALID_ARGUMENT;
}

uint32_t librdp_server_peer_desktop_width(const librdp_server_peer* peer)
{
    return peer ? peer->width : 0;
}

uint32_t librdp_server_peer_desktop_height(const librdp_server_peer* peer)
{
    return peer ? peer->height : 0;
}

librdp_status librdp_server_peer_surface_resize(librdp_server_peer* peer, uint32_t width, uint32_t height)
{
    librdp_status status = LIBRDP_STATUS_OK;
    int was_active = 0;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    was_active = peer->state == LIBRDP_SERVER_PEER_ACTIVE;
    status = rdp_server_surface_allocate(peer, width, height);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.surface.resize",
                                 "surface resize rejected");
        return status;
    }
    rdp_server_emit_surface_event(peer, 0, 0, width, height);
    if (was_active)
    {
        peer->confirm_active_seen = 0;
        peer->synchronize_seen = 0;
        peer->control_seen = 0;
        peer->font_list_seen = 0;
        status = rdp_server_send_demand_active(peer);
        if (status != LIBRDP_STATUS_OK)
            rdp_server_record_status(peer,
                                     status,
                                     rdp_server_component_for_status(status),
                                     "server.surface.resize",
                                     "reactivation failed");
    }
    return status;
}

librdp_status librdp_server_peer_surface_blit_bgra32(librdp_server_peer* peer,
                                                     uint32_t x,
                                                     uint32_t y,
                                                     uint32_t width,
                                                     uint32_t height,
                                                     size_t stride,
                                                     const uint8_t* pixels)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !pixels || stride < (size_t)width * 4u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_server_surface_ensure(peer);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.surface.blit",
                                 "surface allocation failed");
        return status;
    }
    if (!rdp_server_rect_valid(peer, x, y, width, height))
    {
        rdp_server_record_status(peer,
                                 LIBRDP_STATUS_INVALID_ARGUMENT,
                                 LIBRDP_ERROR_COMPONENT_PROTOCOL,
                                 "server.surface.blit",
                                 "surface rectangle rejected");
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    for (uint32_t row = 0; row < height; row++)
    {
        const uint8_t* src = pixels + ((size_t)row * stride);
        uint8_t* dst = peer->framebuffer + ((size_t)(y + row) * peer->framebuffer_stride) + ((size_t)x * 4u);

        memcpy(dst, src, (size_t)width * 4u);
    }
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_surface_present(librdp_server_peer* peer,
                                                 uint32_t x,
                                                 uint32_t y,
                                                 uint32_t width,
                                                 uint32_t height)
{
    librdp_status status = rdp_server_surface_present_rect(peer, x, y, width, height);

    if (peer && status != LIBRDP_STATUS_OK)
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.surface.present",
                                 "surface presentation failed");
    return status;
}

librdp_status librdp_server_peer_send_channel_data(librdp_server_peer* peer,
                                                   uint16_t channel_id,
                                                   const void* data,
                                                   size_t data_len)
{
    uint16_t channel_index = 0;
    rdp_buffer mcs;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (!rdp_server_static_channel_index(peer, channel_id, &channel_index) ||
        !peer->advertised_channel_joined[channel_index])
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (data_len > 0x7fffu)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    rdp_buffer_init(&mcs);
    status = rdp_mcs_write_send_data_indication(&mcs, peer->user_id, channel_id, data, data_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_mcs_pdu(peer, &mcs);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_server_metric_add(&peer->metrics.static_channel_out, 1u);
        rdp_server_metric_add(&peer->metrics.static_channel_bytes_out, (uint64_t)data_len);
    }
    else
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.channel.send",
                                 "static channel send failed");
    rdp_buffer_free(&mcs);
    return status;
}

static librdp_status rdp_server_send_dynamic_packet(librdp_server_peer* peer, const rdp_buffer* packet)
{
    uint16_t static_channel_id = rdp_server_dynamic_static_channel_id(peer);

    if (!peer || !packet || static_channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return librdp_server_peer_send_channel_data(peer, static_channel_id, packet->data, packet->length);
}

librdp_status librdp_server_peer_open_dynamic_channel(librdp_server_peer* peer,
                                                      uint32_t dynamic_channel_id,
                                                      uint8_t priority,
                                                      const char* name)
{
    rdp_server_dynamic_channel* channel = NULL;
    rdp_buffer packet;
    size_t name_len = 0;
    uint8_t channel_id_bytes = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || dynamic_channel_id == 0 || priority > 3u ||
        !rdp_server_dynamic_channel_name_valid(name, &name_len))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE || !peer->dynamic_channels_ready ||
        rdp_server_dynamic_static_channel_id(peer) == 0)
        return LIBRDP_STATUS_STATE;
    if (rdp_server_find_dynamic_channel_any(peer, dynamic_channel_id))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    channel = rdp_server_allocate_dynamic_channel(peer);
    if (!channel)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    channel_id_bytes = rdp_dynamic_channel_select_channel_id_bytes(dynamic_channel_id);
    if (channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&packet);
    status = rdp_dynamic_channel_write_create_request(&packet,
                                                      dynamic_channel_id,
                                                      channel_id_bytes,
                                                      priority,
                                                      name,
                                                      name_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_packet(peer, &packet);
    if (status == LIBRDP_STATUS_OK)
    {
        memset(channel, 0, sizeof(*channel));
        channel->channel_id = dynamic_channel_id;
        channel->channel_id_bytes = channel_id_bytes;
        channel->priority = priority;
        channel->pending_open = 1;
        memcpy(channel->name, name, name_len);
        channel->name[name_len] = '\0';
        rdp_buffer_init(&channel->fragment);
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.dvc.open.request",
                        "channel_id=%u name_len=%u priority=%u",
                        dynamic_channel_id,
                        (unsigned)name_len,
                        (unsigned)priority);
    }
    else
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.dvc.open",
                                 "dynamic channel open request failed");
    rdp_buffer_free(&packet);
    return status;
}

/*
 * Sends application payload on a negotiated dynamic virtual channel.
 * The function fragments oversized messages into DVC DATA_FIRST/DATA PDUs
 * while preserving one logical metrics event for the caller-visible send.
 */
librdp_status librdp_server_peer_send_dynamic_channel_data(librdp_server_peer* peer,
                                                           uint32_t dynamic_channel_id,
                                                           const void* data,
                                                           size_t data_len)
{
    rdp_server_dynamic_channel* channel = NULL;
    const uint8_t* bytes = (const uint8_t*)data;
    rdp_buffer packet;
    size_t offset = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (data_len > RDP_SERVER_DYNAMIC_MESSAGE_MAX)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    channel = rdp_server_find_dynamic_channel(peer, dynamic_channel_id);
    if (!channel)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&packet);
    if (data_len <= RDP_DYNAMIC_CHANNEL_SINGLE_MESSAGE_LIMIT)
    {
        status = rdp_dynamic_channel_write_data(&packet,
                                                dynamic_channel_id,
                                                channel->channel_id_bytes,
                                                data,
                                                data_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_send_dynamic_packet(peer, &packet);
    }
    else
    {
        size_t first_capacity = RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE -
                                rdp_dynamic_channel_data_first_pdu_header_size(channel->channel_id_bytes,
                                                                               (uint32_t)data_len);
        size_t data_capacity = RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE -
                               rdp_dynamic_channel_data_pdu_header_size(channel->channel_id_bytes);
        size_t chunk = data_len < first_capacity ? data_len : first_capacity;

        if (first_capacity == 0 || data_capacity == 0 || data_len > UINT32_MAX)
            status = LIBRDP_STATUS_LIMIT_EXCEEDED;
        if (status == LIBRDP_STATUS_OK)
            status = rdp_dynamic_channel_write_data_first(&packet,
                                                          dynamic_channel_id,
                                                          channel->channel_id_bytes,
                                                          (uint32_t)data_len,
                                                          bytes,
                                                          chunk);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_send_dynamic_packet(peer, &packet);
        offset = chunk;
        while (status == LIBRDP_STATUS_OK && offset < data_len)
        {
            chunk = data_len - offset < data_capacity ? data_len - offset : data_capacity;
            packet.length = 0;
            status = rdp_dynamic_channel_write_data(&packet,
                                                    dynamic_channel_id,
                                                    channel->channel_id_bytes,
                                                    bytes + offset,
                                                    chunk);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_server_send_dynamic_packet(peer, &packet);
            offset += chunk;
        }
    }
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_server_metric_add(&peer->metrics.dynamic_channel_out, 1u);
        rdp_server_metric_add(&peer->metrics.dynamic_channel_bytes_out, (uint64_t)data_len);
    }
    else
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.dvc.send",
                                 "dynamic channel send failed");
    rdp_buffer_free(&packet);
    return status;
}

/*
 * Processes one application-owned UDP2 side-transport datagram.
 * The core validates the wrapper and packet, marks UDP2 active only after a
 * complete valid datagram, and returns an ACK datagram for data packets. Socket
 * ownership remains outside the server object so embedders can integrate UDP2
 * with their own transport loop, firewall policy, or gateway binding.
 */
librdp_status librdp_server_peer_process_udp2_datagram(librdp_server_peer* peer,
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

    if (!peer || !datagram || datagram_len == 0 || !response_len ||
        (!response && response_capacity > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *response_len = 0;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if ((peer->requested_features & (uint32_t)LIBRDP_FEATURE_UDP2_TRANSPORT) == 0 ||
        !peer->multitransport_negotiated)
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
        peer->multitransport_udp2_active = 1;
        rdp_server_metric_add(&peer->metrics.pdu_in, 1u);
        if (ack_wire.length > 0)
            rdp_server_metric_add(&peer->metrics.pdu_out, 1u);
    }
    if (status != LIBRDP_STATUS_OK)
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.udp2.datagram",
                                 "UDP2 datagram processing failed");

    rdp_buffer_free(&ack_wire);
    rdp_buffer_free(&ack_packet);
    rdp_buffer_free(&packet_bytes);
    return status;
}

static int rdp_server_static_channel_joined_named(const librdp_server_peer* peer,
                                                  uint16_t channel_id,
                                                  const char* expected_name)
{
    char name[LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY];
    uint16_t index = 0;

    if (!peer || !expected_name ||
        !rdp_server_static_channel_index(peer, channel_id, &index) ||
        !peer->advertised_channel_joined[index])
        return 0;
    rdp_server_copy_channel_name(name, peer->advertised_channels[index].name);
    return rdp_server_name_equals(name, strlen(name), expected_name);
}

static int rdp_server_dynamic_channel_open_named(librdp_server_peer* peer,
                                                 uint32_t dynamic_channel_id,
                                                 const char* expected_name)
{
    rdp_server_dynamic_channel* channel = rdp_server_find_dynamic_channel(peer, dynamic_channel_id);

    if (!channel || !expected_name)
        return 0;
    return rdp_server_name_equals(channel->name, strlen(channel->name), expected_name);
}

static int rdp_server_tunnel_type_present(const uint32_t* tunnel_types, uint32_t tunnel_count, uint32_t tunnel_type)
{
    if (!tunnel_types)
        return 0;
    for (uint32_t i = 0; i < tunnel_count; i++)
    {
        if (tunnel_types[i] == tunnel_type)
            return 1;
    }
    return 0;
}

static int rdp_server_soft_sync_channels_open(librdp_server_peer* peer,
                                              const rdp_dynamic_channel_soft_sync_channel_list* list)
{
    if (!peer || !list)
        return 0;
    for (uint16_t i = 0; i < list->channel_count; i++)
    {
        uint32_t channel_id = 0;

        if (rdp_dynamic_channel_soft_sync_channel_list_get_id(list, i, &channel_id) != LIBRDP_STATUS_OK ||
            !rdp_server_find_dynamic_channel(peer, channel_id))
            return 0;
    }
    return 1;
}

static librdp_status rdp_server_select_soft_sync_tunnels(librdp_server_peer* peer,
                                                         const rdp_dynamic_channel_soft_sync_request* request,
                                                         uint32_t* tunnel_types,
                                                         uint32_t tunnel_capacity,
                                                         uint32_t* tunnel_count)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !request || !tunnel_types || !tunnel_count)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *tunnel_count = 0;
    if (!peer->multitransport_negotiated ||
        (peer->requested_features & (uint32_t)LIBRDP_FEATURE_UDP_TRANSPORT) == 0)
        return LIBRDP_STATUS_OK;
    for (uint16_t i = 0; i < request->tunnel_count && status == LIBRDP_STATUS_OK; i++)
    {
        rdp_dynamic_channel_soft_sync_channel_list list;

        status = rdp_dynamic_channel_soft_sync_request_get_list(request, i, &list);
        if (status != LIBRDP_STATUS_OK)
            break;
        if (!rdp_server_soft_sync_channels_open(peer, &list))
            continue;
        if (list.tunnel_type != RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_RELIABLE &&
            list.tunnel_type != RDP_DYNAMIC_CHANNEL_TUNNEL_UDP_LOSSY)
            continue;
        if (!rdp_server_tunnel_type_present(tunnel_types, *tunnel_count, list.tunnel_type))
        {
            if (*tunnel_count >= tunnel_capacity)
                return LIBRDP_STATUS_LIMIT_EXCEEDED;
            tunnel_types[*tunnel_count] = list.tunnel_type;
            (*tunnel_count)++;
        }
    }
    return status;
}

static librdp_status rdp_server_send_static_named_buffer(librdp_server_peer* peer,
                                                        uint16_t channel_id,
                                                        const char* expected_name,
                                                        const rdp_buffer* buffer)
{
    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_server_static_channel_joined_named(peer, channel_id, expected_name))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return librdp_server_peer_send_channel_data(peer, channel_id, buffer->data, buffer->length);
}

static librdp_status rdp_server_send_dynamic_named_buffer(librdp_server_peer* peer,
                                                         uint32_t dynamic_channel_id,
                                                         const char* expected_name,
                                                         const rdp_buffer* buffer)
{
    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_server_dynamic_channel_open_named(peer, dynamic_channel_id, expected_name))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return librdp_server_peer_send_dynamic_channel_data(peer, dynamic_channel_id, buffer->data, buffer->length);
}

static int rdp_server_extension_family_compatible(librdp_server_extension_family actual,
                                                  librdp_server_extension_family expected)
{
    if (expected == LIBRDP_SERVER_EXTENSION_UNKNOWN)
        return 0;
    if (actual == expected)
        return 1;
    return actual == LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION &&
           (expected == LIBRDP_SERVER_EXTENSION_SMARTCARD ||
            expected == LIBRDP_SERVER_EXTENSION_PNP);
}

static librdp_status rdp_server_validate_outgoing_extension(librdp_server_extension_family family,
                                                            const char* name,
                                                            size_t name_len,
                                                            const void* payload,
                                                            size_t payload_len)
{
    librdp_server_extension_event event;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!name || (!payload && payload_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = librdp_server_extension_event_init(&event);
    if (status != LIBRDP_STATUS_OK)
        return status;
    event.family = family;
    event.name = name;
    event.name_len = name_len;
    event.payload = payload;
    event.payload_len = payload_len;
    return rdp_server_extension_validate(&event);
}

librdp_status librdp_server_peer_send_static_extension_data(librdp_server_peer* peer,
                                                            librdp_server_extension_family family,
                                                            uint16_t channel_id,
                                                            const void* payload,
                                                            size_t payload_len)
{
    char name[LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY];
    librdp_server_extension_family actual_family = LIBRDP_SERVER_EXTENSION_UNKNOWN;
    librdp_feature feature = (librdp_feature)0;
    uint16_t index = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || (!payload && payload_len > 0) || family == LIBRDP_SERVER_EXTENSION_UNKNOWN)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (!rdp_server_static_channel_index(peer, channel_id, &index) ||
        !peer->advertised_channel_joined[index])
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_server_copy_channel_name(name, peer->advertised_channels[index].name);
    rdp_server_extension_classify_name(name, strlen(name), &actual_family, &feature);
    if (!rdp_server_extension_family_compatible(actual_family, family))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_server_validate_outgoing_extension(actual_family, name, strlen(name), payload, payload_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return librdp_server_peer_send_channel_data(peer, channel_id, payload, payload_len);
}

librdp_status librdp_server_peer_send_dynamic_extension_data(librdp_server_peer* peer,
                                                             librdp_server_extension_family family,
                                                             uint32_t dynamic_channel_id,
                                                             const void* payload,
                                                             size_t payload_len)
{
    rdp_server_dynamic_channel* channel = NULL;
    librdp_server_extension_family actual_family = LIBRDP_SERVER_EXTENSION_UNKNOWN;
    librdp_feature feature = (librdp_feature)0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || (!payload && payload_len > 0) || family == LIBRDP_SERVER_EXTENSION_UNKNOWN)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE)
        return LIBRDP_STATUS_STATE;
    channel = rdp_server_find_dynamic_channel(peer, dynamic_channel_id);
    if (!channel)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_server_extension_classify_name(channel->name, strlen(channel->name), &actual_family, &feature);
    if (!rdp_server_extension_family_compatible(actual_family, family))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_server_validate_outgoing_extension(actual_family,
                                                    channel->name,
                                                    strlen(channel->name),
                                                    payload,
                                                    payload_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return librdp_server_peer_send_dynamic_channel_data(peer, dynamic_channel_id, payload, payload_len);
}

librdp_status librdp_server_peer_send_clipboard_monitor_ready(librdp_server_peer* peer, uint16_t channel_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_clipboard_write_monitor_ready(&payload);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer, channel_id, RDP_SERVER_CLIPBOARD_CHANNEL_NAME, &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_clipboard_capabilities(librdp_server_peer* peer,
                                                             uint16_t channel_id,
                                                             uint32_t general_flags)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_clipboard_write_capabilities(&payload, general_flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer, channel_id, RDP_SERVER_CLIPBOARD_CHANNEL_NAME, &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_clipboard_format_list_response(librdp_server_peer* peer,
                                                                    uint16_t channel_id,
                                                                    int ok)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_clipboard_write_format_list_response(&payload, ok);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer, channel_id, RDP_SERVER_CLIPBOARD_CHANNEL_NAME, &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_echo_response(librdp_server_peer* peer,
                                                    uint32_t dynamic_channel_id,
                                                    const void* payload_data,
                                                    size_t payload_len)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_echo_channel_write_response(&payload, payload_data, payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer, dynamic_channel_id, RDP_ECHO_CHANNEL_NAME, &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_display_single_monitor_layout(librdp_server_peer* peer,
                                                                    uint32_t dynamic_channel_id,
                                                                    uint32_t width,
                                                                    uint32_t height)
{
    rdp_display_control_monitor monitor;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_display_control_make_single_monitor(&monitor, width, height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_display_control_write_monitor_layout(&payload, &monitor, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_DISPLAY_CONTROL_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_graphics_default_caps(librdp_server_peer* peer,
                                                            uint32_t dynamic_channel_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_graphics_write_default_caps_advertise(&payload);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_GRAPHICS_PIPELINE_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_graphics_create_surface(librdp_server_peer* peer,
                                                              uint32_t dynamic_channel_id,
                                                              uint16_t surface_id,
                                                              uint16_t width,
                                                              uint16_t height,
                                                              uint8_t pixel_format)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_graphics_write_create_surface(&payload, surface_id, width, height, pixel_format);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_GRAPHICS_PIPELINE_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_graphics_delete_surface(librdp_server_peer* peer,
                                                              uint32_t dynamic_channel_id,
                                                              uint16_t surface_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_graphics_write_delete_surface(&payload, surface_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_GRAPHICS_PIPELINE_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_graphics_reset(librdp_server_peer* peer,
                                                     uint32_t dynamic_channel_id,
                                                     uint32_t width,
                                                     uint32_t height)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_graphics_write_reset(&payload, width, height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_GRAPHICS_PIPELINE_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_core_input_init(librdp_server_peer* peer, uint32_t dynamic_channel_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_core_input_write_init_request(&payload);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_CORE_INPUT_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_touch_ready(librdp_server_peer* peer,
                                                  uint32_t dynamic_channel_id,
                                                  uint32_t protocol_version,
                                                  uint32_t supported_features,
                                                  int has_supported_features)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_input_channel_write_sc_ready(&payload,
                                              protocol_version,
                                              supported_features,
                                              has_supported_features ? 1u : 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_INPUT_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_mouse_cursor_caps(librdp_server_peer* peer,
                                                        uint32_t dynamic_channel_id)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_mouse_cursor_write_caps_advertise(&payload);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_named_buffer(peer,
                                                      dynamic_channel_id,
                                                      RDP_MOUSE_CURSOR_CHANNEL_NAME,
                                                      &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_video_geometry_update(librdp_server_peer* peer,
                                                            uint16_t channel_id,
                                                            uint32_t message_id,
                                                            const uint8_t presentation_id[16],
                                                            const void* geometry,
                                                            uint32_t geometry_len,
                                                            const void* visible_rect,
                                                            uint32_t visible_rect_len)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&payload);
    status = rdp_video_redirection_write_geometry_update(&payload,
                                                         message_id,
                                                         presentation_id,
                                                         geometry,
                                                         geometry_len,
                                                         visible_rect,
                                                         visible_rect_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_static_named_buffer(peer,
                                                     channel_id,
                                                     RDP_VIDEO_REDIRECTION_CHANNEL_NAME,
                                                     &payload);
    rdp_buffer_free(&payload);
    return status;
}

librdp_status librdp_server_peer_send_desktop_composition_start(librdp_server_peer* peer)
{
    rdp_buffer order;
    rdp_buffer update;
    rdp_buffer slowpath;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE || peer->updates_suppressed)
        return LIBRDP_STATUS_STATE;
    rdp_buffer_init(&order);
    rdp_buffer_init(&update);
    rdp_buffer_init(&slowpath);
    status = rdp_gdi_write_altsec_order(&order, RDP_GDI_ALTSEC_COMPDESK_FIRST, NULL, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_gdi_write_slow_orders_update_payload(&update, 1, order.data, order.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_data_pdu(&slowpath,
                                             peer->share_id,
                                             (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                             RDP_SLOWPATH_DATA_PDU_UPDATE,
                                             update.data,
                                             update.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_slowpath(peer, &slowpath);
    if (status != LIBRDP_STATUS_OK)
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.desktop_composition.start",
                                 "desktop composition order send failed");
    rdp_buffer_free(&slowpath);
    rdp_buffer_free(&update);
    rdp_buffer_free(&order);
    return status;
}

librdp_status librdp_server_peer_close_dynamic_channel(librdp_server_peer* peer, uint32_t dynamic_channel_id)
{
    rdp_server_dynamic_channel* channel = NULL;
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->state != LIBRDP_SERVER_PEER_ACTIVE)
        return LIBRDP_STATUS_STATE;
    channel = rdp_server_find_dynamic_channel(peer, dynamic_channel_id);
    if (!channel)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&packet);
    status = rdp_dynamic_channel_write_close(&packet, dynamic_channel_id, channel->channel_id_bytes);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_dynamic_packet(peer, &packet);
    if (status == LIBRDP_STATUS_OK)
    {
        channel->open = 0;
        peer->dynamic_channel_count--;
        rdp_buffer_free(&channel->fragment);
        rdp_server_emit_dynamic_channel_event(peer, channel, LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_CLOSE, NULL, 0);
    }
    else
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.dvc.close",
                                 "dynamic channel close failed");
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status rdp_server_dynamic_emit_reassembled(librdp_server_peer* peer,
                                                         rdp_server_dynamic_channel* channel,
                                                         const uint8_t* data,
                                                         size_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !channel || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_server_emit_extension_event(peer,
                                             channel->name,
                                             strlen(channel->name),
                                             rdp_server_dynamic_static_channel_id(peer),
                                             channel->channel_id,
                                             channel->priority,
                                             data,
                                             data_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_server_metric_add(&peer->metrics.dynamic_channel_in, 1u);
    rdp_server_metric_add(&peer->metrics.dynamic_channel_bytes_in, (uint64_t)data_len);
    rdp_server_emit_dynamic_channel_event(peer, channel, LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_DATA, data, data_len);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_dynamic_handle_create(librdp_server_peer* peer,
                                                      const uint8_t* data,
                                                      size_t data_len)
{
    rdp_dynamic_channel_create_request request;
    rdp_server_dynamic_channel* channel = NULL;
    rdp_buffer response;
    uint32_t status_code = RDP_DYNAMIC_CHANNEL_STATUS_OK;
    librdp_status status = LIBRDP_STATUS_OK;

    memset(&request, 0, sizeof(request));
    rdp_buffer_init(&response);
    status = rdp_dynamic_channel_parse_create_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (status == LIBRDP_STATUS_OK && request.name_len >= RDP_SERVER_DYNAMIC_CHANNEL_NAME_CAPACITY)
        status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    if (status == LIBRDP_STATUS_OK && rdp_server_find_dynamic_channel_any(peer, request.channel_id))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
    {
        channel = rdp_server_allocate_dynamic_channel(peer);
        if (!channel)
            status = LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    if (status != LIBRDP_STATUS_OK)
        status_code = RDP_DYNAMIC_CHANNEL_STATUS_NOT_SUPPORTED;
    if (rdp_dynamic_channel_write_create_response(&response,
                                                  request.channel_id,
                                                  request.channel_id_bytes ? request.channel_id_bytes : 1u,
                                                  status_code) == LIBRDP_STATUS_OK)
        (void)rdp_server_send_dynamic_packet(peer, &response);
    if (status == LIBRDP_STATUS_OK && channel)
    {
        memset(channel, 0, sizeof(*channel));
        channel->channel_id = request.channel_id;
        channel->channel_id_bytes = request.channel_id_bytes;
        channel->priority = request.priority;
        channel->open = 1;
        memcpy(channel->name, request.name, request.name_len);
        channel->name[request.name_len] = '\0';
        rdp_buffer_init(&channel->fragment);
        peer->dynamic_channel_count++;
        rdp_server_emit_dynamic_channel_event(peer, channel, LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_OPEN, NULL, 0);
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.dvc.create",
                        "channel_id=%u name_len=%u",
                        request.channel_id,
                        (unsigned)request.name_len);
    }
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_server_dynamic_handle_create_response(librdp_server_peer* peer,
                                                               const rdp_dynamic_channel_create_response* response)
{
    rdp_server_dynamic_channel* channel = NULL;

    if (!peer || !response)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    channel = rdp_server_find_pending_dynamic_channel(peer, response->channel_id);
    if (!channel)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (response->status_code != RDP_DYNAMIC_CHANNEL_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.dvc.open.rejected",
                        "channel_id=%u status=0x%08x",
                        response->channel_id,
                        response->status_code);
        rdp_buffer_free(&channel->fragment);
        memset(channel, 0, sizeof(*channel));
        return LIBRDP_STATUS_OK;
    }
    channel->pending_open = 0;
    channel->open = 1;
    peer->dynamic_channel_count++;
    rdp_server_emit_dynamic_channel_event(peer, channel, LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_OPEN, NULL, 0);
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "server.dvc.open.done",
                    "channel_id=%u name_len=%u",
                    channel->channel_id,
                    (unsigned)strlen(channel->name));
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_server_dynamic_handle_data_first(librdp_server_peer* peer,
                                                          const uint8_t* data,
                                                          size_t data_len)
{
    rdp_dynamic_channel_data_first_pdu pdu;
    rdp_server_dynamic_channel* channel = NULL;
    librdp_status status = rdp_dynamic_channel_parse_data_first(data, data_len, &pdu);

    if (status != LIBRDP_STATUS_OK)
        return status;
    channel = rdp_server_find_dynamic_channel(peer, pdu.channel_id);
    if (!channel || channel->fragment.length != 0 || pdu.total_length < pdu.data_len ||
        pdu.total_length > RDP_SERVER_DYNAMIC_MESSAGE_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    channel->fragment_expected = pdu.total_length;
    status = rdp_buffer_append(&channel->fragment, pdu.data, pdu.data_len);
    if (status == LIBRDP_STATUS_OK && channel->fragment.length == channel->fragment_expected)
    {
        status = rdp_server_dynamic_emit_reassembled(peer,
                                                     channel,
                                                     channel->fragment.data,
                                                     channel->fragment.length);
        channel->fragment.length = 0;
        channel->fragment_expected = 0;
    }
    return status;
}

static librdp_status rdp_server_dynamic_handle_data(librdp_server_peer* peer,
                                                    const uint8_t* data,
                                                    size_t data_len)
{
    rdp_dynamic_channel_data_pdu pdu;
    rdp_server_dynamic_channel* channel = NULL;
    librdp_status status = rdp_dynamic_channel_parse_data(data, data_len, &pdu);

    if (status != LIBRDP_STATUS_OK)
        return status;
    channel = rdp_server_find_dynamic_channel(peer, pdu.channel_id);
    if (!channel)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (channel->fragment.length == 0)
        return rdp_server_dynamic_emit_reassembled(peer, channel, pdu.data, pdu.data_len);
    if (channel->fragment.length > (size_t)channel->fragment_expected || pdu.data_len == 0 ||
        pdu.data_len > (size_t)channel->fragment_expected - channel->fragment.length)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_buffer_append(&channel->fragment, pdu.data, pdu.data_len);
    if (status == LIBRDP_STATUS_OK && channel->fragment.length == channel->fragment_expected)
    {
        status = rdp_server_dynamic_emit_reassembled(peer,
                                                     channel,
                                                     channel->fragment.data,
                                                     channel->fragment.length);
        channel->fragment.length = 0;
        channel->fragment_expected = 0;
    }
    return status;
}

static librdp_status rdp_server_dynamic_handle_close(librdp_server_peer* peer,
                                                     const uint8_t* data,
                                                     size_t data_len)
{
    rdp_dynamic_channel_close_pdu pdu;
    rdp_server_dynamic_channel* channel = NULL;
    librdp_status status = rdp_dynamic_channel_parse_close(data, data_len, &pdu);

    if (status != LIBRDP_STATUS_OK)
        return status;
    channel = rdp_server_find_dynamic_channel(peer, pdu.channel_id);
    if (!channel)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    channel->open = 0;
    peer->dynamic_channel_count--;
    rdp_buffer_free(&channel->fragment);
    rdp_server_emit_dynamic_channel_event(peer, channel, LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_CLOSE, NULL, 0);
    return LIBRDP_STATUS_OK;
}

/*
 * Dispatches the drdynvc control stream after the static channel is joined.
 * Capability negotiation must complete before create/data/close/soft-sync
 * commands are accepted; application payload is emitted only after DVC
 * fragmentation is reassembled and extension headers validate. Soft-Sync
 * tunnel responses are intentionally limited to already-open dynamic channel
 * IDs so the server never advertises a side transport for unknown state.
 */
static librdp_status rdp_server_handle_dynamic_channel_message(librdp_server_peer* peer,
                                                               const uint8_t* data,
                                                               size_t data_len)
{
    rdp_dynamic_channel_header header;
    rdp_buffer response;
    librdp_status status = rdp_dynamic_channel_parse_header(data, data_len, &header);

    if (!peer || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_buffer_init(&response);
    if (header.command == RDP_DYNAMIC_CHANNEL_CMD_CAPABILITIES)
    {
        rdp_dynamic_channel_capabilities caps;

        status = rdp_dynamic_channel_parse_capabilities(data, data_len, &caps);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_dynamic_channel_write_capabilities_response(
                &response,
                rdp_dynamic_channel_select_version(caps.version));
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_send_dynamic_packet(peer, &response);
        if (status == LIBRDP_STATUS_OK)
            peer->dynamic_channels_ready = 1;
    }
    else if (!peer->dynamic_channels_ready)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_CREATE)
    {
        rdp_dynamic_channel_create_response create_response;

        memset(&create_response, 0, sizeof(create_response));
        if (rdp_dynamic_channel_parse_create_response(data, data_len, &create_response) == LIBRDP_STATUS_OK &&
            rdp_server_find_pending_dynamic_channel(peer, create_response.channel_id))
            status = rdp_server_dynamic_handle_create_response(peer, &create_response);
        else
            status = rdp_server_dynamic_handle_create(peer, data, data_len);
    }
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST)
        status = rdp_server_dynamic_handle_data_first(peer, data, data_len);
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_DATA)
        status = rdp_server_dynamic_handle_data(peer, data, data_len);
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_CLOSE)
        status = rdp_server_dynamic_handle_close(peer, data, data_len);
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_SOFT_SYNC_REQUEST)
    {
        rdp_dynamic_channel_soft_sync_request request;
        uint32_t tunnel_types[2];
        uint32_t tunnel_count = 0;

        memset(tunnel_types, 0, sizeof(tunnel_types));
        status = rdp_dynamic_channel_parse_soft_sync_request(data, data_len, &request);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_select_soft_sync_tunnels(peer,
                                                         &request,
                                                         tunnel_types,
                                                         (uint32_t)(sizeof(tunnel_types) / sizeof(tunnel_types[0])),
                                                         &tunnel_count);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_dynamic_channel_write_soft_sync_response(&response,
                                                                  tunnel_count > 0 ? tunnel_types : NULL,
                                                                  tunnel_count);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_send_dynamic_packet(peer, &response);
        if (status == LIBRDP_STATUS_OK && tunnel_count > 0)
            peer->multitransport_udp_active = 1;
    }
    else
        status = LIBRDP_STATUS_UNSUPPORTED;
    if (status != LIBRDP_STATUS_OK)
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.dvc.dispatch",
                                 "dynamic channel dispatch failed");
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_server_handle_channel_join(librdp_server_peer* peer, const rdp_tpkt* packet)
{
    const uint8_t* data = NULL;
    size_t data_len = 0;
    rdp_mcs_channel_join_request request;
    rdp_buffer confirm;
    uint16_t required_joins = 0;
    librdp_status status = rdp_server_parse_x224_data_packet(packet, &data, &data_len);

    rdp_buffer_init(&confirm);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_parse_channel_join_request(data, data_len, &request);
    if (status == LIBRDP_STATUS_OK &&
        (request.initiator != peer->user_id || !rdp_server_channel_allowed(peer, request.channel_id)))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_channel_join_confirm(&confirm, peer->user_id, request.channel_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_mcs_pdu(peer, &confirm);
    rdp_buffer_free(&confirm);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        return status;
    }
    if (rdp_server_static_channel_index(peer, request.channel_id, NULL))
    {
        uint16_t channel_index = 0;

        (void)rdp_server_static_channel_index(peer, request.channel_id, &channel_index);
        peer->advertised_channel_joined[channel_index] = 1;
        rdp_server_emit_channel_joined_event(peer, request.channel_id);
    }
    peer->joined_channel_count++;
    required_joins = (uint16_t)(peer->advertised_channel_count + 2u);
    if (peer->joined_channel_count >= required_joins)
        return rdp_server_send_valid_client_license(peer);
    rdp_server_set_state(peer, LIBRDP_SERVER_PEER_CHANNEL_JOINING);
    return LIBRDP_STATUS_OK;
}

/*
 * Validate the client-info PDU sent after licensing and before activation.
 * Only field lengths are retained in trace; credentials stay in the borrowed
 * packet memory and are never copied into the server peer.
 */
static librdp_status rdp_server_handle_client_info(librdp_server_peer* peer, const rdp_tpkt* packet)
{
    const uint8_t* data = NULL;
    size_t data_len = 0;
    rdp_mcs_send_data_indication request;
    rdp_client_info_summary summary;
    librdp_status status = rdp_server_parse_x224_data_packet(packet, &data, &data_len);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_parse_send_data_request(data, data_len, &request);
    if (status == LIBRDP_STATUS_OK &&
        (request.initiator != peer->user_id || request.channel_id != RDP_MCS_GLOBAL_CHANNEL_ID))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK && !peer->standard_security_ready &&
        rdp_server_security_payload_has_flag(request.payload, request.payload_len, RDP_SEC_EXCHANGE_PKT))
        status = rdp_server_handle_security_exchange(peer, request.payload, request.payload_len);
    else if (status == LIBRDP_STATUS_OK)
        status = rdp_server_parse_client_info_security_payload(peer, request.payload, request.payload_len, &summary);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        return status;
    }
    if (!peer->client_info_seen &&
        rdp_server_security_payload_has_flag(request.payload, request.payload_len, RDP_SEC_EXCHANGE_PKT))
        return LIBRDP_STATUS_OK;
    peer->client_info_seen = 1;
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "server.client_info.received",
                    "flags=%u username_bytes=%u domain_bytes=%u password_bytes=%u",
                    summary.flags,
                    summary.username_bytes,
                    summary.domain_bytes,
                    summary.password_bytes);
    status = rdp_server_send_demand_active(peer);
    if (status != LIBRDP_STATUS_OK)
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
    return status;
}

static int rdp_server_security_payload_has_flag(const uint8_t* input, size_t input_len, uint16_t required)
{
    uint16_t flags = 0;
    uint16_t flags_hi = 0;

    if (!input || input_len < 4u)
        return 0;
    flags = (uint16_t)((uint16_t)input[0] | ((uint16_t)input[1] << 8));
    flags_hi = (uint16_t)((uint16_t)input[2] | ((uint16_t)input[3] << 8));
    return flags_hi == 0 && (flags & required) == required;
}

/*
 * Consume the client Security Exchange PDU and arm Standard Security for all
 * following client-to-server encrypted PDUs. The encrypted random is decrypted
 * in the certificate helper, and the plaintext is cleansed immediately after
 * key derivation.
 */
static librdp_status rdp_server_handle_security_exchange(librdp_server_peer* peer,
                                                         const uint8_t* input,
                                                         size_t input_len)
{
    rdp_buffer body;
    rdp_stream stream;
    const uint8_t* encrypted_random = NULL;
    uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
    uint32_t encrypted_random_padded_len = 0;
    uint16_t flags = 0;
    size_t encrypted_random_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !input)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_server_uses_standard_security(peer) || !peer->standard_private_key)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_buffer_init(&body);
    memset(client_random, 0, sizeof(client_random));
    status = rdp_security_unwrap_pdu(NULL, input, input_len, &body, &flags);
    if (status == LIBRDP_STATUS_OK &&
        (flags & (uint16_t)(RDP_SEC_EXCHANGE_PKT | RDP_SEC_LICENSE_ENCRYPT_SC)) !=
            (uint16_t)(RDP_SEC_EXCHANGE_PKT | RDP_SEC_LICENSE_ENCRYPT_SC))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_stream_init(&stream, body.data, body.length);
        if (rdp_stream_read_u32_le(&stream, &encrypted_random_padded_len) != LIBRDP_STATUS_OK ||
            encrypted_random_padded_len < 8u ||
            rdp_stream_remaining(&stream) < encrypted_random_padded_len)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        encrypted_random_len = (size_t)encrypted_random_padded_len - 8u;
        if (rdp_stream_read_bytes(&stream, &encrypted_random, encrypted_random_len) != LIBRDP_STATUS_OK ||
            rdp_stream_skip(&stream, 8u) != LIBRDP_STATUS_OK)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_decrypt_private_secret(peer->standard_private_key,
                                                     encrypted_random,
                                                     encrypted_random_len,
                                                     client_random,
                                                     sizeof(client_random));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_standard_server_init(&peer->standard_security,
                                                   RDP_SECURITY_METHOD_128BIT,
                                                   client_random,
                                                   peer->standard_server_random);
    if (status == LIBRDP_STATUS_OK)
    {
        peer->standard_security_ready = 1;
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.standard_security.exchange.done",
                        "encrypted_random_len=%u",
                        (unsigned)encrypted_random_len);
    }
    OPENSSL_cleanse(client_random, sizeof(client_random));
    rdp_buffer_free(&body);
    return status;
}

static librdp_status rdp_server_parse_client_info_security_payload(librdp_server_peer* peer,
                                                                   const uint8_t* input,
                                                                   size_t input_len,
                                                                   rdp_client_info_summary* summary)
{
    rdp_buffer body;
    rdp_buffer framed;
    uint16_t flags = 0;
    rdp_standard_security_context* security = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !input || !summary)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&body);
    rdp_buffer_init(&framed);
    if (peer->standard_security_ready)
        security = &peer->standard_security;
    status = rdp_security_unwrap_pdu(security, input, input_len, &body, &flags);
    if (status == LIBRDP_STATUS_OK && (flags & RDP_SEC_INFO_PKT) == 0)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_header(&framed, RDP_SEC_INFO_PKT);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&framed, body.data, body.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_parse_client_info_pdu(framed.data, framed.length, summary);
    rdp_buffer_free(&framed);
    rdp_buffer_free(&body);
    return status;
}

static librdp_status rdp_server_unwrap_optional_security_header(librdp_server_peer* peer,
                                                                const uint8_t* input,
                                                                size_t input_len,
                                                                rdp_buffer* storage,
                                                                const uint8_t** output,
                                                                size_t* output_len)
{
    uint16_t flags = 0;
    uint16_t flags_hi = 0;
    uint16_t allowed = (uint16_t)(RDP_SEC_EXCHANGE_PKT | RDP_SEC_ENCRYPT | RDP_SEC_INFO_PKT |
                                  RDP_SEC_LICENSE_PKT | RDP_SEC_LICENSE_ENCRYPT_SC |
                                  RDP_SEC_SECURE_CHECKSUM);

    if ((!input && input_len > 0) || !storage || !output || !output_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *output = input;
    *output_len = input_len;
    if (input_len < 4u)
        return LIBRDP_STATUS_OK;
    flags = (uint16_t)((uint16_t)input[0] | ((uint16_t)input[1] << 8));
    flags_hi = (uint16_t)((uint16_t)input[2] | ((uint16_t)input[3] << 8));
    if (flags_hi != 0 || (flags & (uint16_t)~allowed) != 0)
        return LIBRDP_STATUS_OK;
    if ((flags & RDP_SEC_ENCRYPT) != 0 && (!peer || !peer->standard_security_ready))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    storage->length = 0;
    if (rdp_security_unwrap_pdu((flags & RDP_SEC_ENCRYPT) != 0 ? &peer->standard_security : NULL,
                                input,
                                input_len,
                                storage,
                                NULL) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *output = storage->data;
    *output_len = storage->length;
    return LIBRDP_STATUS_OK;
}

/*
 * Dispatch one post-MCS client packet. Global-channel slow-path data drives
 * activation, input, refresh, and output-suppression state; joined static
 * channels are routed to the application callback with borrowed payload
 * views. Malformed runtime input closes the peer because continuing would
 * desynchronize channel and activation state.
 */
static librdp_status rdp_server_handle_runtime_data(librdp_server_peer* peer, const rdp_tpkt* packet)
{
    const uint8_t* data = NULL;
    size_t data_len = 0;
    rdp_mcs_send_data_indication request;
    rdp_slowpath_share_control_header header;
    rdp_buffer security_payload;
    const uint8_t* runtime_payload = NULL;
    size_t runtime_payload_len = 0;
    librdp_status status = rdp_server_parse_x224_data_packet(packet, &data, &data_len);

    rdp_buffer_init(&security_payload);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_parse_send_data_request(data, data_len, &request);
    if (status == LIBRDP_STATUS_OK && request.initiator != peer->user_id)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                              RDP_TRACE_LEVEL_DEBUG,
                              "server.mcs.send_data.request",
                              "state=%d initiator=%u channel_id=%u payload_len=%u",
                              (int)peer->state,
                              request.initiator,
                              request.channel_id,
                              (unsigned)request.payload_len);
        rdp_trace_hexdump("server.mcs.send_data.request",
                          RDP_TRACE_SENSITIVITY_HEADER,
                          request.payload,
                          request.payload_len);
        status = rdp_server_unwrap_optional_security_header(peer,
                                                            request.payload,
                                                            request.payload_len,
                                                            &security_payload,
                                                            &runtime_payload,
                                                            &runtime_payload_len);
    }
    if (status == LIBRDP_STATUS_OK && request.channel_id != RDP_MCS_GLOBAL_CHANNEL_ID)
    {
        uint16_t channel_index = 0;

        if (!rdp_server_static_channel_index(peer, request.channel_id, &channel_index) ||
            !peer->advertised_channel_joined[channel_index])
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else if (channel_index == peer->dynamic_channel_static_index)
            status = rdp_server_handle_dynamic_channel_message(peer, runtime_payload, runtime_payload_len);
        else
        {
            char name[LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY];

            rdp_server_copy_channel_name(name, peer->advertised_channels[channel_index].name);
            status = rdp_server_emit_extension_event(peer,
                                                     name,
                                                     strlen(name),
                                                     request.channel_id,
                                                     0,
                                                     0,
                                                     runtime_payload,
                                                     runtime_payload_len);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
                rdp_buffer_free(&security_payload);
                return status;
            }
            rdp_server_metric_add(&peer->metrics.static_channel_in, 1u);
            rdp_server_metric_add(&peer->metrics.static_channel_bytes_in, (uint64_t)runtime_payload_len);
            if (peer->channel_callback)
            {
                librdp_server_channel_event event;

                memset(&event, 0, sizeof(event));
                event.version = LIBRDP_SERVER_CHANNEL_EVENT_VERSION;
                event.size = (uint32_t)sizeof(event);
                event.type = LIBRDP_SERVER_CHANNEL_EVENT_STATIC_DATA;
                event.channel_id = request.channel_id;
                event.name = name;
                event.name_len = strlen(name);
                event.data = runtime_payload;
                event.data_len = runtime_payload_len;
                peer->channel_callback(peer, &event, peer->channel_callback_user_data);
            }
        }
        if (status != LIBRDP_STATUS_OK)
            rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        rdp_buffer_free(&security_payload);
        return status;
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_parse_share_control_header(runtime_payload, runtime_payload_len, &header);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "server.slowpath.header.failed",
                        "status=%s payload_len=%u",
                        librdp_status_name(status),
                        (unsigned)runtime_payload_len);
        rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        rdp_buffer_free(&security_payload);
        return status;
    }
    rdp_trace_event_level(RDP_TRACE_PROTOCOL,
                          RDP_TRACE_LEVEL_DEBUG,
                          "server.slowpath.header",
                          "pdu_type=%u payload_len=%u",
                          header.pdu_type,
                          (unsigned)runtime_payload_len);
    if ((header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_CONFIRM_ACTIVE)
    {
        peer->confirm_active_seen = 1;
        status = rdp_server_send_activation_responses(peer);
        if (status != LIBRDP_STATUS_OK)
            rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        rdp_buffer_free(&security_payload);
        return status;
    }
    if ((header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_DATA)
    {
        rdp_slowpath_data_pdu pdu;
        librdp_server_input_event event;

        status = rdp_slowpath_parse_data_pdu(runtime_payload, runtime_payload_len, &pdu);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
            rdp_buffer_free(&security_payload);
            return status;
        }
        if (pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SYNCHRONIZE)
        {
            peer->synchronize_seen = 1;
            if (librdp_server_input_event_init(&event) == LIBRDP_STATUS_OK)
            {
                event.type = LIBRDP_SERVER_INPUT_SYNCHRONIZE;
                rdp_server_emit_input(peer, &event);
            }
        }
        else if (pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_CONTROL)
        {
            peer->control_seen = 1;
            if (librdp_server_input_event_init(&event) == LIBRDP_STATUS_OK && pdu.payload_len >= 2u)
            {
                event.type = LIBRDP_SERVER_INPUT_CONTROL;
                event.control_action = (uint16_t)((uint16_t)pdu.payload[0] | ((uint16_t)pdu.payload[1] << 8));
                rdp_server_emit_input(peer, &event);
            }
        }
        else if (pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_FONT_LIST)
        {
            peer->font_list_seen = 1;
            if (librdp_server_input_event_init(&event) == LIBRDP_STATUS_OK)
            {
                event.type = LIBRDP_SERVER_INPUT_FONT_LIST;
                rdp_server_emit_input(peer, &event);
            }
            status = rdp_server_send_font_map(peer);
            if (status == LIBRDP_STATUS_OK)
                rdp_server_set_state(peer, LIBRDP_SERVER_PEER_ACTIVE);
            else
                rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
            rdp_buffer_free(&security_payload);
            return status;
        }
        else if (pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_INPUT)
            status = rdp_server_handle_input_events(peer, pdu.payload, pdu.payload_len);
        else if (pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_REFRESH_RECT)
            status = rdp_server_handle_refresh_rect(peer, pdu.payload, pdu.payload_len);
        else if (pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_SUPPRESS_OUTPUT)
            status = rdp_server_handle_suppress_output(peer, pdu.payload, pdu.payload_len);
        if (status != LIBRDP_STATUS_OK)
            rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        rdp_buffer_free(&security_payload);
        return status;
    }
    rdp_buffer_free(&security_payload);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_get_pollfds(librdp_server_peer* peer,
                                             struct pollfd* fds,
                                             size_t capacity,
                                             size_t* count)
{
    if (!peer || !count || (!fds && capacity > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->fd < 0 || peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    *count = 1;
    if (capacity == 0)
        return LIBRDP_STATUS_OK;
    if (capacity < 1)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&fds[0], 0, sizeof(fds[0]));
    fds[0].fd = peer->fd;
    fds[0].events = POLLIN;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_notify_poll(librdp_server_peer* peer, const struct pollfd* fds, size_t count)
{
    int matched = 0;

    if (!peer || !fds || count == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->fd < 0 || peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    for (size_t i = 0; i < count; i++)
    {
        if (fds[i].fd == peer->fd)
        {
            peer->pending_revents = (short)(peer->pending_revents | fds[i].revents);
            matched = 1;
        }
    }
    return matched ? LIBRDP_STATUS_OK : LIBRDP_STATUS_INVALID_ARGUMENT;
}

librdp_status librdp_server_peer_dispatch_pending(librdp_server_peer* peer)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->fd < 0 || peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    if (peer->pending_revents == 0)
        return LIBRDP_STATUS_OK;
    return librdp_server_peer_run_once(peer, 0);
}

/*
 * Advance one externally-driven server peer phase. TLS handshaking is handled
 * before TPKT parsing because encrypted peers switch transport semantics after
 * the X.224 confirm; every later state consumes exactly one protocol packet
 * and records status at the public boundary.
 */
librdp_status librdp_server_peer_run_once(librdp_server_peer* peer, int timeout_ms)
{
    rdp_tpkt packet;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t packet_len = 0;

    if (!peer || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (peer->fd < 0 || peer->state == LIBRDP_SERVER_PEER_CLOSED)
        return LIBRDP_STATUS_STATE;
    if (peer->state == LIBRDP_SERVER_PEER_NEW)
        rdp_server_set_state(peer, LIBRDP_SERVER_PEER_NEGOTIATING);
    if (peer->state == LIBRDP_SERVER_PEER_TLS_HANDSHAKING)
    {
        status = rdp_server_start_tls(peer, timeout_ms);
        if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_TIMEOUT)
        {
            rdp_server_metric_add(&peer->metrics.errors, 1u);
            rdp_server_record_status(peer,
                                     status,
                                     LIBRDP_ERROR_COMPONENT_TLS,
                                     "server.transport.tls.accept",
                                     "server TLS handshake failed");
            rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        }
        return status;
    }
    if (peer->state == LIBRDP_SERVER_PEER_NLA_AUTHENTICATING)
    {
        status = rdp_server_handle_credssp(peer, timeout_ms);
        if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_TIMEOUT)
        {
            rdp_server_metric_add(&peer->metrics.errors, 1u);
            rdp_server_record_status(peer,
                                     status,
                                     LIBRDP_ERROR_COMPONENT_CREDSSP,
                                     "server.credssp",
                                     "server NLA exchange failed");
            rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_FAILED);
        }
        return status;
    }
    status = rdp_server_read_tpkt(peer, timeout_ms, &packet, &packet_len);
    if (status != LIBRDP_STATUS_OK)
    {
        if (status != LIBRDP_STATUS_TIMEOUT)
            rdp_server_record_status(peer,
                                     status,
                                     rdp_server_component_for_status(status),
                                     "server.peer.read",
                                     "peer packet read failed");
        return status;
    }
    if (peer->state == LIBRDP_SERVER_PEER_NEGOTIATING)
        status = rdp_server_handle_x224(peer, &packet);
    else if (peer->state == LIBRDP_SERVER_PEER_X224_CONFIRMED)
        status = rdp_server_handle_mcs_connect_initial(peer, &packet);
    else if (peer->state == LIBRDP_SERVER_PEER_MCS_CONNECTED)
        status = rdp_server_handle_erect_domain(peer, &packet);
    else if (peer->state == LIBRDP_SERVER_PEER_DOMAIN_READY)
        status = rdp_server_handle_attach_user(peer, &packet);
    else if (peer->state == LIBRDP_SERVER_PEER_USER_ATTACHED ||
             peer->state == LIBRDP_SERVER_PEER_CHANNEL_JOINING)
        status = rdp_server_handle_channel_join(peer, &packet);
    else if (peer->state == LIBRDP_SERVER_PEER_LICENSING)
        status = rdp_server_handle_client_info(peer, &packet);
    else if (peer->state == LIBRDP_SERVER_PEER_ACTIVATING || peer->state == LIBRDP_SERVER_PEER_ACTIVE)
        status = rdp_server_handle_runtime_data(peer, &packet);
    else
        status = LIBRDP_STATUS_STATE;
    if (packet_len > 0 && peer->input.length >= packet_len)
    {
        librdp_status consume_status = rdp_buffer_consume(&peer->input, packet_len);

        if (status == LIBRDP_STATUS_OK && consume_status != LIBRDP_STATUS_OK)
            status = consume_status;
    }
    if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_TIMEOUT)
    {
        rdp_server_metric_add(&peer->metrics.errors, 1u);
        rdp_server_record_status(peer,
                                 status,
                                 rdp_server_component_for_status(status),
                                 "server.peer.dispatch",
                                 "peer dispatch failed");
    }
    return status;
}

librdp_server_peer_state librdp_server_peer_get_state(const librdp_server_peer* peer)
{
    if (!peer)
        return LIBRDP_SERVER_PEER_FAILED;
    return peer->state;
}

static int rdp_server_static_channel_name_equals(const char stored[8], const char* name)
{
    size_t stored_len = 0;
    size_t name_len = 0;

    if (!stored || !name)
        return 0;
    stored_len = rdp_server_channel_name_len(stored);
    name_len = strlen(name);
    return name_len == stored_len && name_len <= 8u && memcmp(stored, name, name_len) == 0;
}

static int rdp_server_peer_static_channel_joined_named(const librdp_server_peer* peer, const char* name)
{
    if (!peer || !name)
        return 0;
    for (uint16_t i = 0; i < peer->advertised_channel_count; i++)
    {
        if (peer->advertised_channel_joined[i] &&
            rdp_server_static_channel_name_equals(peer->advertised_channels[i].name, name))
            return 1;
    }
    return 0;
}

static int rdp_server_peer_dynamic_channel_open_named(const librdp_server_peer* peer, const char* name)
{
    if (!peer || !name)
        return 0;
    for (uint32_t i = 0; i < RDP_SERVER_MAX_DYNAMIC_CHANNELS; i++)
    {
        const rdp_server_dynamic_channel* channel = &peer->dynamic_channels[i];

        if (channel->open && strcmp(channel->name, name) == 0)
            return 1;
    }
    return 0;
}

static void rdp_server_finish_peer_feature_status(librdp_feature_status* status, int negotiated, int active)
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

static int rdp_server_peer_feature_backend_ready(const librdp_server_peer* peer, librdp_feature feature)
{
    if (!rdp_server_feature_has_runtime(feature))
        return 0;
    if (!rdp_server_feature_needs_application_backend(feature))
        return 1;
    return peer && (peer->backend_features & (uint32_t)feature) != 0;
}

/*
 * Resolve peer-local feature state from the negotiated server runtime, not from
 * parser availability. The requested/built/backend flags are prepared by the
 * generic feature layer; this function only marks features active when the
 * matching static or dynamic channel is actually joined/open for this peer.
 */
static void rdp_server_peer_fill_runtime_feature_status(const librdp_server_peer* peer,
                                                        librdp_feature feature,
                                                        librdp_feature_status* status)
{
    int negotiated = 0;

    if (!peer || !status || !status->requested || !status->built || !status->backend_ready)
        return;
    switch (feature)
    {
        case LIBRDP_FEATURE_AUDIO_OUTPUT:
            negotiated = rdp_server_peer_static_channel_joined_named(peer, RDP_AUDIO_OUTPUT_CHANNEL_NAME);
            break;
        case LIBRDP_FEATURE_AUDIO_INPUT:
            negotiated = rdp_server_peer_dynamic_channel_open_named(peer, RDP_AUDIO_INPUT_CHANNEL_NAME);
            break;
        case LIBRDP_FEATURE_VIDEO:
            negotiated = rdp_server_peer_static_channel_joined_named(peer, RDP_VIDEO_REDIRECTION_CHANNEL_NAME) ||
                         rdp_server_peer_dynamic_channel_open_named(peer,
                                                                    RDP_VIDEO_OPTIMIZED_CONTROL_CHANNEL) ||
                         rdp_server_peer_dynamic_channel_open_named(peer, RDP_VIDEO_OPTIMIZED_DATA_CHANNEL);
            break;
        case LIBRDP_FEATURE_GEOMETRY_TRACKING:
            negotiated = rdp_server_peer_static_channel_joined_named(peer, RDP_VIDEO_REDIRECTION_CHANNEL_NAME);
            break;
        case LIBRDP_FEATURE_CAMERA:
            negotiated = rdp_server_peer_dynamic_channel_open_named(peer,
                                                                    RDP_VIDEO_CAPTURE_CONTROL_CHANNEL_NAME) ||
                         rdp_server_peer_dynamic_channel_open_named(peer, RDP_VIDEO_CAPTURE_CHANNEL_NAME);
            break;
        case LIBRDP_FEATURE_SMARTCARD:
        case LIBRDP_FEATURE_PNP:
            negotiated = rdp_server_peer_static_channel_joined_named(peer, RDP_DEVICE_REDIRECTION_CHANNEL_NAME);
            break;
        case LIBRDP_FEATURE_USB:
            negotiated = rdp_server_peer_dynamic_channel_open_named(peer, RDP_USB_REDIRECTION_CHANNEL_NAME);
            break;
        case LIBRDP_FEATURE_WEBAUTHN:
            negotiated = rdp_server_peer_dynamic_channel_open_named(peer, RDP_WEBAUTHN_CHANNEL_NAME);
            break;
        case LIBRDP_FEATURE_RAIL:
            negotiated = rdp_server_peer_static_channel_joined_named(peer, RDP_REMOTE_PROGRAMS_CHANNEL_NAME);
            break;
        case LIBRDP_FEATURE_CR2:
            negotiated = rdp_server_peer_dynamic_channel_open_named(peer, RDP_COMPOSITED_CHANNEL_NAME);
            break;
        case LIBRDP_FEATURE_ECHO:
            negotiated = rdp_server_peer_dynamic_channel_open_named(peer, RDP_ECHO_CHANNEL_NAME);
            break;
        case LIBRDP_FEATURE_DISPLAY_CONTROL:
            negotiated = rdp_server_peer_dynamic_channel_open_named(peer, RDP_DISPLAY_CONTROL_CHANNEL_NAME);
            break;
        case LIBRDP_FEATURE_DESKTOP_COMPOSITION:
            negotiated = peer->state == LIBRDP_SERVER_PEER_ACTIVE;
            break;
        case LIBRDP_FEATURE_TELEMETRY:
            negotiated = rdp_server_peer_dynamic_channel_open_named(peer, RDP_TELEMETRY_DVC_CHANNEL_NAME) ||
                         rdp_server_peer_static_channel_joined_named(peer, RDP_TELEMETRY_CHANNEL_NAME);
            break;
        case LIBRDP_FEATURE_MULTIPARTY:
            negotiated = rdp_server_peer_static_channel_joined_named(peer, RDP_MULTIPARTY_CHANNEL_NAME);
            break;
        case LIBRDP_FEATURE_MULTITRANSPORT:
            rdp_server_finish_peer_feature_status(status,
                                                  peer->multitransport_negotiated,
                                                  peer->multitransport_negotiated &&
                                                      (peer->multitransport_udp_active ||
                                                       peer->multitransport_udp2_active));
            return;
        case LIBRDP_FEATURE_UDP_TRANSPORT:
            rdp_server_finish_peer_feature_status(status,
                                                  peer->multitransport_negotiated,
                                                  peer->multitransport_udp_active);
            return;
        case LIBRDP_FEATURE_UDP2_TRANSPORT:
            rdp_server_finish_peer_feature_status(status,
                                                  peer->multitransport_negotiated,
                                                  peer->multitransport_udp2_active);
            return;
        default:
            return;
    }
    rdp_server_finish_peer_feature_status(status, negotiated, negotiated);
}

librdp_status librdp_server_peer_get_feature_status(const librdp_server_peer* peer,
                                                    librdp_feature feature,
                                                    librdp_feature_status* status)
{
    if (!peer || !status || !rdp_server_valid_single_feature(feature))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_server_fill_feature_status(peer->requested_features,
                                   feature,
                                   rdp_server_peer_feature_backend_ready(peer, feature),
                                   status);
    rdp_server_peer_fill_runtime_feature_status(peer, feature, status);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_get_metrics(const librdp_server_peer* peer, librdp_server_metrics* metrics)
{
    if (!peer || !metrics ||
        metrics->version != LIBRDP_SERVER_METRICS_VERSION ||
        metrics->size < sizeof(librdp_server_metrics))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *metrics = peer->metrics;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_reset_metrics(librdp_server_peer* peer)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return librdp_server_metrics_init(&peer->metrics);
}

librdp_status librdp_server_peer_get_last_status(const librdp_server_peer* peer, librdp_server_status* status)
{
    if (!peer || !rdp_server_status_valid(status))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *status = peer->last_status;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_peer_close(librdp_server_peer* peer)
{
    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_server_close_peer(peer, LIBRDP_SERVER_PEER_CLOSED);
    return LIBRDP_STATUS_OK;
}

void librdp_server_peer_free(librdp_server_peer* peer)
{
    if (!peer)
        return;
    if (peer->tls)
    {
        SSL_set_quiet_shutdown(peer->tls, 1);
        (void)SSL_shutdown(peer->tls);
        SSL_free(peer->tls);
    }
    if (peer->tls_context)
        SSL_CTX_free(peer->tls_context);
    EVP_PKEY_free(peer->standard_private_key);
    rdp_security_standard_clear(&peer->standard_security);
    rdp_server_dynamic_channels_reset(peer);
    if (peer->credssp_security_ready)
    {
        OPENSSL_cleanse(&peer->credssp_security, sizeof(peer->credssp_security));
        peer->credssp_security_ready = 0;
    }
    OPENSSL_cleanse(peer->credssp_server_challenge, sizeof(peer->credssp_server_challenge));
    OPENSSL_cleanse(peer->credssp_client_nonce, sizeof(peer->credssp_client_nonce));
    if (peer->fd >= 0)
        rdp_socket_close(peer->fd);
    rdp_buffer_free(&peer->input);
    rdp_buffer_free(&peer->standard_certificate);
    rdp_buffer_free(&peer->credssp_target_name);
    rdp_buffer_free(&peer->credssp_target_info);
    free(peer->framebuffer);
    free(peer->server_name);
    free(peer->tls_certificate_path);
    free(peer->tls_private_key_path);
    free(peer->nla_domain);
    free(peer->nla_username);
    rdp_server_secure_free(peer->nla_password);
    free(peer);
}
