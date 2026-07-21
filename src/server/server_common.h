/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: shared server constants and protocol type dependencies.
 * Invariants: constants and private types remain outside the public ABI.
 * Ownership: this header declares no independently owned state.
 * Threading: synchronization follows the listener and peer owner contracts.
 * Trust boundary: domain modules validate remote data before committing state.
 */

#ifndef RDP_SERVER_COMMON_H
#define RDP_SERVER_COMMON_H

#include "server/server_internal.h"

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
#include "channels/virtual_channel.h"
#include "channels/webauthn_channel.h"
#include "clipboard/clipboard.h"
#include "graphics/bitmap.h"
#include "graphics/gdi_orders.h"
#include "licensing/licensing.h"
#include "platform/socket.h"
#include "protocol/fastpath.h"
#include "protocol/mcs.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "transport/udp_transport.h"

#define RDP_SERVER_DEFAULT_BACKLOG 4u
#define RDP_SERVER_DEFAULT_MAX_PEERS 16u
#define RDP_SERVER_DEFAULT_WIDTH 1024u
#define RDP_SERVER_DEFAULT_HEIGHT 768u
#define RDP_SERVER_MAX_TEXT 512u
#define RDP_SERVER_MAX_BACKLOG 128u
#define RDP_SERVER_MAX_PEERS 1024u
#define RDP_SERVER_MIN_DESKTOP_SIZE LIBRDP_DESKTOP_MIN_DIMENSION
#define RDP_SERVER_MAX_DESKTOP_SIZE LIBRDP_DESKTOP_MAX_DIMENSION
#define RDP_SERVER_NEGOTIATION_FAILURE_SSL_REQUIRED 0x00000001u
#define RDP_SERVER_NEGOTIATION_FAILURE_SSL_NOT_ALLOWED 0x00000002u
#define RDP_SERVER_NEGOTIATION_FAILURE_SSL_CERT_NOT_ON_SERVER 0x00000003u
#define RDP_SERVER_NEGOTIATION_FAILURE_HYBRID_REQUIRED 0x00000005u
#define RDP_SERVER_INITIAL_READ_MAX 65535u
#define RDP_SERVER_CREDSSP_MESSAGE_MAX 1048576u
#define RDP_SERVER_NTLM_AV_EOL 0x0000u
#define RDP_SERVER_NTLM_AV_NB_COMPUTER_NAME 0x0001u
#define RDP_SERVER_NTLM_AV_NB_DOMAIN_NAME 0x0002u
#define RDP_SERVER_NTLM_AV_DNS_COMPUTER_NAME 0x0003u
#define RDP_SERVER_NTLM_AV_DNS_DOMAIN_NAME 0x0004u
#define RDP_SERVER_NTLM_AV_TIMESTAMP 0x0007u
#define RDP_SERVER_STANDARD_ENCRYPTION_LEVEL 3u
#define RDP_SERVER_DYNAMIC_MESSAGE_MAX (64u * 1024u * 1024u)
#define RDP_SERVER_STATIC_MESSAGE_MAX (64u * 1024u * 1024u)
#define RDP_SERVER_STATIC_CHANNEL_CHUNK_SIZE 1600u
#define RDP_SERVER_FASTPATH_PACKET_MAX 0x3fffu
#define RDP_SERVER_FASTPATH_HEADER_MAX 3u
#define RDP_SERVER_FASTPATH_SIGNATURE_SIZE 8u
#define RDP_SERVER_FASTPATH_UPDATE_HEADER_SIZE 3u
#define RDP_SERVER_FASTPATH_FRAGMENT_DATA_MAX \
    (RDP_SERVER_FASTPATH_PACKET_MAX - \
     RDP_SERVER_FASTPATH_HEADER_MAX - \
     RDP_SERVER_FASTPATH_SIGNATURE_SIZE - \
     RDP_SERVER_FASTPATH_UPDATE_HEADER_SIZE)
#define RDP_SERVER_GRAPHICS_FRAME_QUEUE_LIMIT_DEFAULT 4u
#define RDP_SERVER_GRAPHICS_FRAME_QUEUE_LIMIT_MAX 1024u
#define RDP_SERVER_MAX_CLIPBOARD_FORMATS 4096u
#define RDP_SERVER_CLIPBOARD_CHANNEL_NAME "cliprdr"
#define RDP_SERVER_UDP_ACK_VECTOR_MAX_RUN RDP_UDP_ACK_VECTOR_MAX_RUN
#define RDP_SERVER_UDP_ACK_VECTOR_MAX_BYTES RDP_UDP_ACK_VECTOR_ENCODED_MAX_SIZE
#define RDP_SERVER_UDP_MAX_REPORTABLE_PENDING RDP_UDP_MAX_REPORTABLE_GAP
#define RDP_SERVER_UDP2_ACK_VECTOR_MAX_RUN RDP_UDP2_ACK_VECTOR_MAX_RUN
#define RDP_SERVER_UDP2_ACK_VECTOR_MAX_BYTES RDP_UDP2_ACK_VECTOR_ENCODED_MAX_SIZE
#define RDP_SERVER_UDP2_MAX_REPORTABLE_LOSS RDP_UDP2_MAX_REPORTABLE_GAP
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

#endif
