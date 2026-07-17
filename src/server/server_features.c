/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: feature readiness, extension state, status, and metrics.
 * Invariants: state transitions and wire behavior are preserved from the
 * server orchestrator; cross-domain calls use private module contracts.
 * Ownership: server and peer objects own retained state; input payloads are
 * borrowed for the duration of each call.
 * Threading: callers serialize access to each listener and peer.
 * Trust boundary: remote protocol data is validated before state is committed.
 */

#include "server/server_features.h"

#include "server/server_listener.h"
#include "server/server_protocol.h"

#include "common/buffer.h"
#include "common/charset.h"
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
#include "channels/pnp_redirection.h"
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
#include <openssl/x509err.h>
#include <ctype.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

void rdp_server_metric_add(uint64_t* metric, uint64_t value)
{
    if (!metric)
        return;
    if (UINT64_MAX - *metric < value)
        *metric = UINT64_MAX;
    else
        *metric += value;
}

static size_t rdp_server_size_min(size_t a, size_t b)
{
    return a < b ? a : b;
}

int rdp_server_valid_feature_mask(librdp_feature feature)
{
    uint32_t value = (uint32_t)feature;

    return value != 0 && (value & ~RDP_SERVER_KNOWN_FEATURES) == 0;
}

int rdp_server_valid_single_feature(librdp_feature feature)
{
    uint32_t value = (uint32_t)feature;

    return rdp_server_valid_feature_mask(feature) && (value & (value - 1u)) == 0;
}

int rdp_server_extension_family_valid(librdp_server_extension_family family)
{
    return family > LIBRDP_SERVER_EXTENSION_UNKNOWN &&
           family <= LIBRDP_SERVER_EXTENSION_GEOMETRY_TRACKING;
}

uint64_t rdp_server_extension_family_bit(librdp_server_extension_family family)
{
    if (!rdp_server_extension_family_valid(family) || (unsigned)family >= 64u)
        return 0;
    return UINT64_C(1) << (unsigned)family;
}

int rdp_server_extension_provider_ready(uint64_t providers,
                                               librdp_server_extension_family family)
{
    const uint64_t bit = rdp_server_extension_family_bit(family);

    return bit != 0 && (providers & bit) != 0;
}

librdp_feature rdp_server_feature_for_extension_family(librdp_server_extension_family family)
{
    switch (family)
    {
        case LIBRDP_SERVER_EXTENSION_AUDIO_OUTPUT:
            return LIBRDP_FEATURE_AUDIO_OUTPUT;
        case LIBRDP_SERVER_EXTENSION_AUDIO_INPUT:
            return LIBRDP_FEATURE_AUDIO_INPUT;
        case LIBRDP_SERVER_EXTENSION_VIDEO:
            return LIBRDP_FEATURE_VIDEO;
        case LIBRDP_SERVER_EXTENSION_CAMERA:
            return LIBRDP_FEATURE_CAMERA;
        case LIBRDP_SERVER_EXTENSION_SMARTCARD:
            return LIBRDP_FEATURE_SMARTCARD;
        case LIBRDP_SERVER_EXTENSION_USB:
            return LIBRDP_FEATURE_USB;
        case LIBRDP_SERVER_EXTENSION_PNP:
            return LIBRDP_FEATURE_PNP;
        case LIBRDP_SERVER_EXTENSION_WEBAUTHN:
            return LIBRDP_FEATURE_WEBAUTHN;
        case LIBRDP_SERVER_EXTENSION_RAIL:
            return LIBRDP_FEATURE_RAIL;
        case LIBRDP_SERVER_EXTENSION_CR2:
            return LIBRDP_FEATURE_CR2;
        case LIBRDP_SERVER_EXTENSION_ECHO:
            return LIBRDP_FEATURE_ECHO;
        case LIBRDP_SERVER_EXTENSION_DISPLAY_CONTROL:
            return LIBRDP_FEATURE_DISPLAY_CONTROL;
        case LIBRDP_SERVER_EXTENSION_TELEMETRY:
            return LIBRDP_FEATURE_TELEMETRY;
        case LIBRDP_SERVER_EXTENSION_DESKTOP_COMPOSITION:
            return LIBRDP_FEATURE_DESKTOP_COMPOSITION;
        case LIBRDP_SERVER_EXTENSION_MULTIPARTY:
            return LIBRDP_FEATURE_MULTIPARTY;
        case LIBRDP_SERVER_EXTENSION_GEOMETRY_TRACKING:
            return LIBRDP_FEATURE_GEOMETRY_TRACKING;
        default:
            return (librdp_feature)0;
    }
}

int rdp_server_feature_extension_provider_ready(uint64_t providers, librdp_feature feature)
{
    for (uint32_t family = (uint32_t)LIBRDP_SERVER_EXTENSION_UNKNOWN + 1u;
         family <= (uint32_t)LIBRDP_SERVER_EXTENSION_GEOMETRY_TRACKING;
         family++)
    {
        if (rdp_server_feature_for_extension_family((librdp_server_extension_family)family) == feature &&
            rdp_server_extension_provider_ready(providers, (librdp_server_extension_family)family))
            return 1;
    }
    return 0;
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

int rdp_server_feature_provider_mask_valid(librdp_feature feature)
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

int rdp_server_listener_feature_backend_ready(const librdp_server* server, librdp_feature feature)
{
    if (!rdp_server_feature_has_runtime(feature))
        return 0;
    if (!rdp_server_feature_needs_application_backend(feature))
        return 1;
    if (server && (server->backend_features & (uint32_t)feature) != 0)
        return 1;
    return server && rdp_server_feature_extension_provider_ready(server->backend_extension_families, feature);
}

void rdp_server_fill_feature_status(uint32_t requested_features,
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

librdp_status librdp_server_clipboard_state_init(librdp_server_clipboard_state* state)
{
    if (!state)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(state, 0, sizeof(*state));
    state->version = LIBRDP_SERVER_CLIPBOARD_STATE_VERSION;
    state->size = sizeof(*state);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_server_extension_state_init(librdp_server_extension_state* state)
{
    if (!state)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(state, 0, sizeof(*state));
    state->version = LIBRDP_SERVER_EXTENSION_STATE_VERSION;
    state->size = sizeof(*state);
    state->last_status = LIBRDP_STATUS_OK;
    return LIBRDP_STATUS_OK;
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
    if (peer && (peer->backend_features & (uint32_t)feature) != 0)
        return 1;
    return peer && rdp_server_feature_extension_provider_ready(peer->backend_extension_families, feature);
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
    uint32_t caller_size = 0;
    size_t copy_size = 0;

    if (!peer || !metrics ||
        metrics->version != LIBRDP_SERVER_METRICS_VERSION ||
        metrics->size < offsetof(librdp_server_metrics, udp2_datagrams_in))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    caller_size = metrics->size;
    copy_size = rdp_server_size_min(caller_size, sizeof(peer->metrics));
    memset(metrics, 0, copy_size);
    memcpy(metrics, &peer->metrics, copy_size);
    metrics->version = LIBRDP_SERVER_METRICS_VERSION;
    metrics->size = (uint32_t)copy_size;
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
