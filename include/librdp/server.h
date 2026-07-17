/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_SERVER_H
#define LIBRDP_SERVER_H

#include <stddef.h>
#include <stdint.h>
#include <poll.h>

#include <librdp/error.h>
#include <librdp/settings.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup librdp_server Server API
 * @brief Server-side listener, peer negotiation, and activation primitives.
 * @{
 */

#define LIBRDP_SERVER_CONFIG_VERSION 1u /**< Current librdp_server_config version. */
#define LIBRDP_SERVER_INPUT_EVENT_VERSION 1u /**< Current librdp_server_input_event version. */
#define LIBRDP_SERVER_STATIC_CHANNEL_INFO_VERSION 1u /**< Current librdp_server_static_channel_info version. */
#define LIBRDP_SERVER_DYNAMIC_CHANNEL_INFO_VERSION 1u /**< Current librdp_server_dynamic_channel_info version. */
#define LIBRDP_SERVER_CHANNEL_EVENT_VERSION 1u /**< Current librdp_server_channel_event version. */
#define LIBRDP_SERVER_EXTENSION_EVENT_VERSION 1u /**< Current librdp_server_extension_event version. */
#define LIBRDP_SERVER_EVENT_VERSION 1u /**< Current librdp_server_event version. */
#define LIBRDP_SERVER_STATUS_VERSION 1u /**< Current librdp_server_status version. */
#define LIBRDP_SERVER_METRICS_VERSION 1u /**< Current librdp_server_metrics version. */
#define LIBRDP_SERVER_CLIPBOARD_STATE_VERSION 1u /**< Current librdp_server_clipboard_state version. */
#define LIBRDP_SERVER_EXTENSION_STATE_VERSION 1u /**< Current librdp_server_extension_state version. */
#define LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY 9u /**< Static-channel name storage including NUL. */
#define LIBRDP_SERVER_DYNAMIC_CHANNEL_NAME_CAPACITY 64u /**< Dynamic-channel name storage including NUL. */
#define LIBRDP_SERVER_PHASE_CAPACITY 32u /**< Server status phase storage including NUL. */
#define LIBRDP_SERVER_MESSAGE_CAPACITY 128u /**< Server status message storage including NUL. */

/**
 * @brief Opaque server listener handle.
 *
 * The handle owns server configuration copied at creation. Listener sockets
 * and accepted peers are introduced by the server runtime APIs.
 *
 * @since 0.1.0
 */
typedef struct librdp_server librdp_server;

/**
 * @brief Opaque server-side peer handle.
 *
 * A peer owns one accepted transport socket and its minimal negotiation state.
 * Peers are created by librdp_server_accept() and freed with
 * librdp_server_peer_free().
 *
 * @since 0.1.0
 */
typedef struct librdp_server_peer librdp_server_peer;

/**
 * @brief Server-side peer lifecycle state.
 *
 * The server runtime advances one explicit protocol phase at a time. ACTIVE
 * means the base connection and activation handshake completed; higher-level
 * desktop rendering, virtual channels, and policy remain application-driven.
 *
 * @since 0.1.0
 */
typedef enum librdp_server_peer_state
{
    LIBRDP_SERVER_PEER_NEW = 0,         /**< Peer was accepted and no bytes have been processed. */
    LIBRDP_SERVER_PEER_NEGOTIATING = 1, /**< Peer is processing initial connection negotiation. */
    LIBRDP_SERVER_PEER_X224_CONFIRMED = 2, /**< X.224 was accepted and MCS/GCC validation is pending. */
    LIBRDP_SERVER_PEER_CLOSING = 3,     /**< Peer shutdown is in progress. */
    LIBRDP_SERVER_PEER_CLOSED = 4,      /**< Peer socket is closed. */
    LIBRDP_SERVER_PEER_FAILED = 5,      /**< Peer failed because input or I/O was invalid. */
    LIBRDP_SERVER_PEER_MCS_CONNECTED = 6, /**< MCS Connect-Initial was accepted and Connect-Response was sent. */
    LIBRDP_SERVER_PEER_DOMAIN_READY = 7,  /**< Erect Domain Request was accepted. */
    LIBRDP_SERVER_PEER_USER_ATTACHED = 8, /**< Attach User Request was accepted and confirmed. */
    LIBRDP_SERVER_PEER_CHANNEL_JOINING = 9, /**< Channel Join Requests are being accepted. */
    LIBRDP_SERVER_PEER_ACTIVATING = 10,  /**< Demand Active was sent and client activation PDUs are pending. */
    LIBRDP_SERVER_PEER_ACTIVE = 11,      /**< Client confirmed activation and the peer is ready for runtime PDUs. */
    LIBRDP_SERVER_PEER_LICENSING = 12,   /**< Server licensing completion was sent before activation. */
    LIBRDP_SERVER_PEER_TLS_HANDSHAKING = 13, /**< TLS transport handshake is in progress after X.224. */
    LIBRDP_SERVER_PEER_NLA_AUTHENTICATING = 14 /**< CredSSP/NLA exchange is in progress over TLS. */
} librdp_server_peer_state;

/**
 * @brief Server-side input event kind.
 *
 * These values describe client-originated slow-path input and activation
 * control PDUs after the peer has completed the base connection sequence.
 * Payload fields in librdp_server_input_event are selected by this value.
 *
 * @since 0.1.0
 */
typedef enum librdp_server_input_type
{
    LIBRDP_SERVER_INPUT_SYNCHRONIZE = 1,       /**< Client Synchronize PDU. */
    LIBRDP_SERVER_INPUT_CONTROL = 2,           /**< Client Control PDU. */
    LIBRDP_SERVER_INPUT_FONT_LIST = 3,         /**< Client Font List PDU. */
    LIBRDP_SERVER_INPUT_SCANCODE_KEY = 4,      /**< Keyboard scancode event. */
    LIBRDP_SERVER_INPUT_UNICODE_KEY = 5,       /**< Unicode keyboard event. */
    LIBRDP_SERVER_INPUT_MOUSE = 6,             /**< Pointer event. */
    LIBRDP_SERVER_INPUT_EXTENDED_MOUSE = 7,    /**< Extended pointer event. */
    LIBRDP_SERVER_INPUT_REFRESH_RECT = 8,      /**< Client requested a rectangle refresh. */
    LIBRDP_SERVER_INPUT_SUPPRESS_OUTPUT = 9    /**< Client changed output suppression state. */
} librdp_server_input_type;

/**
 * @brief One client-originated server input event.
 *
 * Initialize caller-owned instances with librdp_server_input_event_init() when
 * constructing synthetic tests. Events delivered to callbacks are owned by the
 * library and valid only until the callback returns. No pointer fields are
 * retained by the library.
 *
 * @since 0.1.0
 */
typedef struct librdp_server_input_event
{
    uint32_t version;             /**< Struct version, LIBRDP_SERVER_INPUT_EVENT_VERSION. */
    uint32_t size;                /**< Size of this struct in bytes. */
    librdp_server_input_type type; /**< Input or control event kind. */
    uint32_t event_time;          /**< Client event timestamp for input events, or zero. */
    uint16_t flags;               /**< RDP input flags or suppress-output allow flag. */
    uint16_t param1;              /**< Raw first protocol parameter. */
    uint16_t param2;              /**< Raw second protocol parameter. */
    uint16_t x;                   /**< Pointer or rectangle x coordinate when applicable. */
    uint16_t y;                   /**< Pointer or rectangle y coordinate when applicable. */
    uint16_t width;               /**< Rectangle width when applicable. */
    uint16_t height;              /**< Rectangle height when applicable. */
    uint16_t control_action;      /**< Control action for LIBRDP_SERVER_INPUT_CONTROL. */
} librdp_server_input_event;

/**
 * @brief Static virtual-channel metadata exposed by a server-side peer.
 *
 * Channel names are copied into name and always NUL-terminated when returned
 * by librdp_server_peer_static_channel_at(). channel_id is valid only after
 * the client joined that channel.
 *
 * @since 0.1.0
 */
typedef struct librdp_server_static_channel_info
{
    uint32_t version; /**< Struct version, LIBRDP_SERVER_STATIC_CHANNEL_INFO_VERSION. */
    uint32_t size;    /**< Size of this struct in bytes. */
    uint16_t channel_id; /**< Joined MCS channel identifier, or zero before join. */
    uint32_t flags;      /**< Client-advertised channel flags. */
    int joined;          /**< Non-zero when the channel join completed. */
    char name[LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY]; /**< NUL-terminated static-channel name. */
} librdp_server_static_channel_info;

/**
 * @brief Server-side dynamic virtual-channel metadata.
 *
 * Dynamic channel IDs are negotiated inside the drdynvc static channel and are
 * valid only while open is non-zero. name is copied and NUL-terminated.
 *
 * @since 0.1.0
 */
typedef struct librdp_server_dynamic_channel_info
{
    uint32_t version; /**< Struct version, LIBRDP_SERVER_DYNAMIC_CHANNEL_INFO_VERSION. */
    uint32_t size;    /**< Size of this struct in bytes. */
    uint32_t channel_id; /**< Dynamic virtual-channel identifier. */
    uint8_t priority;    /**< Negotiated DVC priority class. */
    int open;            /**< Non-zero while the dynamic channel is open. */
    char name[LIBRDP_SERVER_DYNAMIC_CHANNEL_NAME_CAPACITY]; /**< NUL-terminated dynamic-channel name. */
} librdp_server_dynamic_channel_info;

/**
 * @brief Server channel callback event kind.
 *
 * Static-channel payloads and dynamic-channel lifecycle/data notifications use
 * the same callback but different payload fields.
 *
 * @since 0.1.0
 */
typedef enum librdp_server_channel_event_type
{
    LIBRDP_SERVER_CHANNEL_EVENT_STATIC_DATA = 1,  /**< Static virtual-channel payload. */
    LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_OPEN = 2, /**< Dynamic virtual channel opened. */
    LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_DATA = 3, /**< Dynamic virtual-channel payload. */
    LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_CLOSE = 4 /**< Dynamic virtual channel closed. */
} librdp_server_channel_event_type;

/**
 * @brief Server-side extension protocol family.
 *
 * Values identify normalized server dispatch for optional RDP extensions.
 * They are independent from librdp_feature because some legacy static
 * channels, such as clipboard, are always negotiated by name rather than by a
 * public feature bit.
 *
 * @since 0.1.0
 */
typedef enum librdp_server_extension_family
{
    LIBRDP_SERVER_EXTENSION_UNKNOWN = 0,             /**< Unrecognized extension channel. */
    LIBRDP_SERVER_EXTENSION_CLIPBOARD = 1,           /**< Clipboard redirection static channel. */
    LIBRDP_SERVER_EXTENSION_DEVICE_REDIRECTION = 2,  /**< Core device redirection static channel. */
    LIBRDP_SERVER_EXTENSION_AUDIO_OUTPUT = 3,        /**< Audio output static channel. */
    LIBRDP_SERVER_EXTENSION_AUDIO_INPUT = 4,         /**< Audio input dynamic channel. */
    LIBRDP_SERVER_EXTENSION_VIDEO = 5,               /**< Video redirection static or dynamic channel. */
    LIBRDP_SERVER_EXTENSION_CAMERA = 6,              /**< Camera capture dynamic channel. */
    LIBRDP_SERVER_EXTENSION_SMARTCARD = 7,           /**< Smartcard traffic over device redirection. */
    LIBRDP_SERVER_EXTENSION_USB = 8,                 /**< USB redirection dynamic channel. */
    LIBRDP_SERVER_EXTENSION_PNP = 9,                 /**< Plug-and-play device redirection. */
    LIBRDP_SERVER_EXTENSION_WEBAUTHN = 10,           /**< WebAuthn dynamic channel. */
    LIBRDP_SERVER_EXTENSION_RAIL = 11,               /**< Remote Programs static channel. */
    LIBRDP_SERVER_EXTENSION_CR2 = 12,                /**< Composited remoting dynamic channel. */
    LIBRDP_SERVER_EXTENSION_ECHO = 13,               /**< Echo diagnostics dynamic channel. */
    LIBRDP_SERVER_EXTENSION_DISPLAY_CONTROL = 14,    /**< Display Control dynamic channel. */
    LIBRDP_SERVER_EXTENSION_GRAPHICS = 15,           /**< Graphics Pipeline dynamic channel. */
    LIBRDP_SERVER_EXTENSION_CORE_INPUT = 16,         /**< Core Input dynamic channel. */
    LIBRDP_SERVER_EXTENSION_TOUCH_INPUT = 17,        /**< Touch and pen input dynamic channel. */
    LIBRDP_SERVER_EXTENSION_MOUSE_CURSOR = 18,       /**< Mouse Cursor dynamic channel. */
    LIBRDP_SERVER_EXTENSION_AUTH_REDIRECTION = 19,   /**< Authentication redirection dynamic channel. */
    LIBRDP_SERVER_EXTENSION_TELEMETRY = 20,          /**< Telemetry dynamic channel. */
    LIBRDP_SERVER_EXTENSION_DESKTOP_COMPOSITION = 21, /**< Desktop composition channel. */
    LIBRDP_SERVER_EXTENSION_MULTIPARTY = 22,          /**< Multiparty dynamic channel. */
    LIBRDP_SERVER_EXTENSION_FILESYSTEM = 23,          /**< Drive filesystem traffic over device redirection. */
    LIBRDP_SERVER_EXTENSION_PRINTER = 24,             /**< Printer traffic over device redirection. */
    LIBRDP_SERVER_EXTENSION_SERIAL_PORT = 25,         /**< Serial-port traffic over device redirection. */
    LIBRDP_SERVER_EXTENSION_PARALLEL_PORT = 26,       /**< Parallel-port traffic over device redirection. */
    LIBRDP_SERVER_EXTENSION_GEOMETRY_TRACKING = 27    /**< Geometry tracking state used by video remoting. */
} librdp_server_extension_family;

/**
 * @brief One clipboard format entry advertised by the server.
 *
 * name points to borrowed bytes valid for the duration of the send call. When
 * long_names is non-zero in librdp_server_peer_send_clipboard_format_list(),
 * name is UTF-16LE without a required trailing NUL; when long_names is zero,
 * name is an ASCII format name. name may be NULL only when name_len is zero.
 *
 * @since 0.1.0
 */
typedef struct librdp_server_clipboard_format
{
    uint32_t format_id; /**< Clipboard format identifier. */
    const void* name;   /**< Borrowed format-name bytes, or NULL for unnamed formats. */
    size_t name_len;    /**< Number of bytes available at name. */
} librdp_server_clipboard_format;

/**
 * @brief Snapshot of server-side clipboard runtime state.
 *
 * The structure contains protocol state and request correlation identifiers
 * only. Clipboard payload bytes and format names are never stored here.
 *
 * @since 0.1.0
 */
typedef struct librdp_server_clipboard_state
{
    size_t size;      /**< Structure size in bytes, set by init. */
    uint32_t version; /**< Structure version, LIBRDP_SERVER_CLIPBOARD_STATE_VERSION. */
    uint8_t monitor_ready_sent;     /**< Server Monitor Ready PDU has been sent. */
    uint8_t monitor_ready_received; /**< Client Monitor Ready PDU has been accepted. */
    uint8_t capabilities_sent;      /**< Server clipboard capabilities have been sent. */
    uint8_t capabilities_received;  /**< Client clipboard capabilities have been accepted. */
    uint8_t formats_sent;           /**< Server format list has been sent. */
    uint8_t formats_accepted;       /**< Client acknowledged the latest server format list. */
    uint8_t pending_format_request; /**< A server format-data request is awaiting a response. */
    uint8_t pending_file_request;   /**< A server file-contents request is awaiting a response. */
    uint8_t locked;                 /**< A clipboard lock is currently tracked. */
    uint32_t format_count;          /**< Last accepted or sent format-count metadata. */
    uint32_t pending_format_id;     /**< Format identifier for the pending data request, if any. */
    uint32_t pending_file_stream_id; /**< Stream id for the pending file request, if any. */
    uint32_t locked_clip_data_id;   /**< Lock identifier when locked is non-zero. */
    uint32_t reconnect_generation;  /**< Incremented when clipboard runtime state is reset for reconnect. */
} librdp_server_clipboard_state;

/**
 * @brief Server-side static virtual-channel data event.
 *
 * name and data are borrowed and valid only until the channel callback
 * returns. Applications must copy payload bytes they need to retain.
 *
 * @since 0.1.0
 */
typedef struct librdp_server_channel_event
{
    uint32_t version; /**< Struct version, LIBRDP_SERVER_CHANNEL_EVENT_VERSION. */
    uint32_t size;    /**< Size of this struct in bytes. */
    uint16_t channel_id; /**< MCS channel identifier that received data. */
    const char* name;    /**< Borrowed static-channel name; never NULL for known static channels. */
    size_t name_len;     /**< Length in bytes of name, excluding the NUL terminator. */
    const uint8_t* data; /**< Borrowed channel payload; may be NULL when data_len is zero. */
    size_t data_len;     /**< Length in bytes of data. */
    librdp_server_channel_event_type type; /**< Static or dynamic channel event kind. */
    uint32_t dynamic_channel_id; /**< Dynamic channel ID for dynamic events, otherwise zero. */
    uint8_t dynamic_priority; /**< Dynamic channel priority for dynamic events, otherwise zero. */
} librdp_server_channel_event;

/**
 * @brief Normalized server-side extension event.
 *
 * The event is emitted after the server has validated the outer channel packet
 * and extracted the protocol family and message type. payload is borrowed and
 * valid only until the extension callback returns. message_type and flags are
 * protocol-specific values such as packet identifiers, order types, or command
 * identifiers. status is the result of lightweight header validation.
 *
 * @since 0.1.0
 */
typedef struct librdp_server_extension_event
{
    uint32_t version; /**< Struct version, LIBRDP_SERVER_EXTENSION_EVENT_VERSION. */
    uint32_t size;    /**< Size of this struct in bytes. */
    librdp_server_extension_family family; /**< Normalized extension family. */
    librdp_feature feature; /**< Matching feature bit when one exists, otherwise zero. */
    librdp_status status;   /**< Header validation status for this payload. */
    uint16_t channel_id;    /**< Static MCS channel id carrying the payload, or zero. */
    uint32_t dynamic_channel_id; /**< Dynamic channel id, or zero for static channels. */
    uint8_t dynamic_priority;    /**< Dynamic channel priority, or zero for static channels. */
    const char* name;            /**< Borrowed channel name; never NULL for known channels. */
    size_t name_len;             /**< Channel name length in bytes. */
    uint32_t message_type;       /**< Protocol-specific PDU, order, or function identifier. */
    uint32_t flags;              /**< Protocol-specific flags or component value. */
    const uint8_t* payload;      /**< Borrowed extension payload; may be NULL only when payload_len is zero. */
    size_t payload_len;          /**< Extension payload length in bytes. */
} librdp_server_extension_event;

/**
 * @brief Versioned runtime state snapshot for one server extension family.
 *
 * The structure contains negotiated state, request counters, and channel
 * identifiers owned by the server peer. It never stores extension payload bytes,
 * filenames, APDUs, media samples, credentials, or user content. The caller owns
 * the snapshot and must initialize it with librdp_server_extension_state_init().
 *
 * @since 0.1.0
 */
typedef struct librdp_server_extension_state
{
    size_t size;      /**< Structure size in bytes, set by init. */
    uint32_t version; /**< Structure version, LIBRDP_SERVER_EXTENSION_STATE_VERSION. */
    librdp_server_extension_family family; /**< Extension family described by this snapshot. */
    librdp_feature feature; /**< Public feature bit associated with family, or zero. */
    uint8_t provider_ready; /**< Application provider is enabled for this family. */
    uint8_t negotiated;     /**< Matching channel or runtime path was negotiated. */
    uint8_t active;         /**< Runtime path is open and can process data. */
    uint8_t capability_seen; /**< Capability or setup message was observed for the family. */
    uint8_t open;           /**< Static or dynamic channel is open for this family. */
    uint8_t pending_open;   /**< A server-initiated dynamic open is awaiting a response. */
    uint8_t closing;        /**< A close is in progress for this family. */
    uint8_t cancelled;      /**< Pending family work was cancelled by the application. */
    uint16_t static_channel_id; /**< Joined static channel id, or zero. */
    uint32_t dynamic_channel_id; /**< Open dynamic channel id, or zero. */
    uint8_t dynamic_priority;    /**< Dynamic channel priority, or zero. */
    uint32_t last_message_type;  /**< Last validated message type for this family. */
    uint32_t last_flags;         /**< Last protocol-specific flags for this family. */
    uint64_t rx_messages;        /**< Validated inbound messages for this family. */
    uint64_t tx_messages;        /**< Outbound messages sent for this family. */
    uint64_t rx_bytes;           /**< Validated inbound payload bytes for this family. */
    uint64_t tx_bytes;           /**< Outbound payload bytes sent for this family. */
    uint32_t pending_requests;   /**< Family-level pending request count. */
    uint32_t open_count;         /**< Number of successful opens observed for this family. */
    uint32_t close_count;        /**< Number of closes or cleanup resets observed for this family. */
    uint32_t timeout_count;      /**< Timeouts recorded for this family. */
    uint32_t reconnect_generation; /**< Incremented when family state resets for reconnect. */
    librdp_status last_status;   /**< Last family-specific status, or LIBRDP_STATUS_OK. */
} librdp_server_extension_state;

/**
 * @brief Server event discriminator.
 *
 * Events are synchronous notifications emitted from public server calls on the
 * same thread that drives the listener or peer. Payload fields in
 * librdp_server_event are selected by this value.
 *
 * @since 0.1.0
 */
typedef enum librdp_server_event_type
{
    LIBRDP_SERVER_EVENT_NONE = 0,          /**< No event payload is active. */
    LIBRDP_SERVER_EVENT_STATE_CHANGED = 1, /**< Peer state changed. */
    LIBRDP_SERVER_EVENT_ERROR = 2,         /**< A peer runtime boundary recorded an error. */
    LIBRDP_SERVER_EVENT_SURFACE = 3,       /**< A surface resize or dirty rectangle was accepted. */
    LIBRDP_SERVER_EVENT_CHANNEL_JOINED = 4 /**< A static channel completed MCS join. */
} librdp_server_event_type;

/**
 * @brief Server runtime event payload.
 *
 * Events are stack-owned by the library and valid only until the event
 * callback returns. phase and message are borrowed immutable tokens for the
 * callback duration only; copy them if they are needed later.
 *
 * @since 0.1.0
 */
typedef struct librdp_server_event
{
    uint32_t version; /**< Struct version, LIBRDP_SERVER_EVENT_VERSION. */
    uint32_t size;    /**< Size of this struct in bytes. */
    librdp_server_event_type type; /**< Event kind. */
    librdp_server_peer_state old_state; /**< Previous peer state for state-change events. */
    librdp_server_peer_state new_state; /**< Current peer state for state-change events. */
    librdp_status status; /**< Status associated with error events, otherwise LIBRDP_STATUS_OK. */
    librdp_error_component component; /**< Component associated with status. */
    const char* phase; /**< Borrowed phase token; may be NULL. */
    const char* message; /**< Borrowed redacted message; may be NULL. */
    uint16_t channel_id; /**< Static channel identifier for channel events. */
    uint32_t x;          /**< Surface rectangle x coordinate for surface events. */
    uint32_t y;          /**< Surface rectangle y coordinate for surface events. */
    uint32_t width;      /**< Surface or desktop width in pixels for surface events. */
    uint32_t height;     /**< Surface or desktop height in pixels for surface events. */
} librdp_server_event;

/**
 * @brief Versioned snapshot of the last server peer status.
 *
 * The struct is fully owned by the caller. phase and message are copied into
 * fixed-size arrays and always NUL-terminated on success, so the snapshot does
 * not borrow from the peer.
 *
 * @since 0.1.0
 */
typedef struct librdp_server_status
{
    uint32_t version; /**< Struct version, LIBRDP_SERVER_STATUS_VERSION. */
    uint32_t size;    /**< Size of this struct in bytes. */
    librdp_status status; /**< Last recorded status, or LIBRDP_STATUS_OK. */
    librdp_error_component component; /**< Component that recorded status. */
    librdp_server_peer_state state; /**< Peer state observed when status was recorded. */
    char phase[LIBRDP_SERVER_PHASE_CAPACITY]; /**< NUL-terminated phase token. */
    char message[LIBRDP_SERVER_MESSAGE_CAPACITY]; /**< NUL-terminated redacted message. */
} librdp_server_status;

/**
 * @brief Versioned server-side metrics snapshot.
 *
 * Metrics are monotonic for one peer until librdp_server_peer_reset_metrics()
 * is called. They count server runtime observations only: accepted packets,
 * emitted PDUs, static-channel traffic, input callbacks, framebuffer updates,
 * feature-gating rejections, and detected error/limit paths.
 *
 * @since 0.1.0
 */
typedef struct librdp_server_metrics
{
    uint32_t version; /**< Struct version, LIBRDP_SERVER_METRICS_VERSION. */
    uint32_t size;    /**< Size of this struct in bytes. */
    uint64_t bytes_read; /**< Bytes read from the peer socket by the server runtime. */
    uint64_t bytes_written; /**< Bytes written to the peer socket by the server runtime. */
    uint64_t pdu_in; /**< Top-level client packets accepted by the server runtime. */
    uint64_t pdu_out; /**< Top-level server packets sent by the server runtime. */
    uint64_t input_events; /**< Client input/control events delivered to the input callback. */
    uint64_t static_channel_in; /**< Static-channel payloads delivered to the channel callback. */
    uint64_t static_channel_out; /**< Static-channel payloads sent by public server APIs. */
    uint64_t static_channel_bytes_in; /**< Static-channel payload bytes received. */
    uint64_t static_channel_bytes_out; /**< Static-channel payload bytes sent. */
    uint64_t dynamic_channel_in; /**< Dynamic-channel payloads delivered to the channel callback. */
    uint64_t dynamic_channel_out; /**< Dynamic-channel payloads sent by public server APIs. */
    uint64_t dynamic_channel_bytes_in; /**< Dynamic-channel payload bytes received. */
    uint64_t dynamic_channel_bytes_out; /**< Dynamic-channel payload bytes sent. */
    uint64_t surface_updates; /**< Dirty rectangles sent from the server framebuffer. */
    uint64_t feature_rejections; /**< Feature requests rejected because no server runtime exists. */
    uint64_t limits_rejected; /**< Inputs rejected by explicit size, count, or geometry limits. */
    uint64_t errors; /**< Runtime errors observed at the public server boundary. */
} librdp_server_metrics;

/**
 * @brief Server-side input callback.
 *
 * Called synchronously from librdp_server_peer_run_once() on the thread driving
 * the peer. The event object is callback-owned and becomes invalid when the
 * callback returns. The callback must not free the peer.
 *
 * @since 0.1.0
 */
typedef void (*librdp_server_input_callback)(librdp_server_peer* peer,
                                             const librdp_server_input_event* event,
                                             void* user_data);

/**
 * @brief Server-side static-channel callback.
 *
 * Called synchronously from librdp_server_peer_run_once() on the thread driving
 * the peer. The event object and payload bytes are valid only for the callback
 * duration. The callback must not free the peer.
 *
 * @since 0.1.0
 */
typedef void (*librdp_server_channel_callback)(librdp_server_peer* peer,
                                               const librdp_server_channel_event* event,
                                               void* user_data);

/**
 * @brief Server-side dynamic-channel accept callback.
 *
 * Called synchronously from librdp_server_peer_run_once() when a client sends a
 * DVC CREATE request. name is borrowed and valid only until the callback
 * returns; it is not guaranteed to be NUL-terminated, so consumers must use
 * name_len. Return non-zero to accept the channel or zero to reject it with a
 * protocol-level not-supported response.
 *
 * @since 0.1.0
 */
typedef int (*librdp_server_dynamic_channel_accept_callback)(librdp_server_peer* peer,
                                                             uint32_t dynamic_channel_id,
                                                             uint8_t priority,
                                                             const char* name,
                                                             size_t name_len,
                                                             void* user_data);

/**
 * @brief Server-side normalized extension callback.
 *
 * Called synchronously from librdp_server_peer_run_once() on the thread driving
 * the peer. The event object, channel name, and payload are valid only for the
 * callback duration. The callback must not free the peer.
 *
 * @since 0.1.0
 */
typedef void (*librdp_server_extension_callback)(librdp_server_peer* peer,
                                                 const librdp_server_extension_event* event,
                                                 void* user_data);

/**
 * @brief Server-side runtime event callback.
 *
 * Called synchronously from public server functions on the same serialized
 * server/peer owner thread. The event pointer and borrowed strings are valid
 * only until the callback returns.
 *
 * @since 0.1.0
 */
typedef void (*librdp_server_event_callback)(librdp_server_peer* peer,
                                             const librdp_server_event* event,
                                             void* user_data);

/**
 * @brief Versioned server listener configuration.
 *
 * Initialize with librdp_server_config_init(). String fields are borrowed only
 * for the duration of librdp_server_new() and copied into the server object.
 * bind_address may be NULL to listen on loopback. port zero asks the operating
 * system to allocate an ephemeral port.
 *
 * @since 0.1.0
 */
typedef struct librdp_server_config
{
    uint32_t version;      /**< Struct version, LIBRDP_SERVER_CONFIG_VERSION. */
    uint32_t size;         /**< Size of this struct in bytes. */
    const char* bind_address; /**< Optional bind address copied on creation; NULL uses loopback. */
    uint16_t port;         /**< TCP listen port, or zero for an ephemeral port. */
    uint32_t backlog;      /**< Listen backlog; zero uses a safe default. */
    uint32_t max_peers;    /**< Maximum peers accepted during one listen lifetime; zero uses a safe default. */
    uint32_t width;        /**< Default desktop width used during activation; zero uses default. */
    uint32_t height;       /**< Default desktop height used during activation; zero uses default. */
    const char* server_name; /**< Optional diagnostic server name copied on creation. */
    librdp_security_mode security_mode; /**< Server security policy; STANDARD is the default. */
    const char* tls_certificate_path; /**< PEM certificate path for TLS/NLA modes; copied on creation. */
    const char* tls_private_key_path; /**< PEM private-key path for TLS/NLA modes; copied on creation. */
    const char* nla_domain; /**< Optional NLA account domain; copied on creation and may be NULL. */
    const char* nla_username; /**< Required username for NLA mode; copied on creation. */
    const char* nla_password; /**< Required password for NLA mode; copied and cleansed on release. */
} librdp_server_config;

/**
 * @brief Initialize a server configuration with safe defaults.
 *
 * Defaults bind to loopback on an ephemeral port, use a small listen backlog,
 * and reserve a 1024x768 desktop size for activation.
 *
 * @param[out] config Caller-owned config object; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * config is NULL.
 *
 * @note Thread-safety: this function writes only caller-owned storage.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_config_init(librdp_server_config* config);

/**
 * @brief Initialize a server input event value.
 *
 * @param[out] event Caller-owned event object; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * event is NULL.
 *
 * @note Thread-safety: this function writes only caller-owned storage.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_input_event_init(librdp_server_input_event* event);

/**
 * @brief Initialize server static-channel metadata.
 *
 * @param[out] info Caller-owned metadata object; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * info is NULL.
 *
 * @note Thread-safety: this function writes only caller-owned storage.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_static_channel_info_init(librdp_server_static_channel_info* info);

/**
 * @brief Initialize server dynamic-channel metadata.
 *
 * @param[out] info Caller-owned metadata object; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * info is NULL.
 *
 * @note Thread-safety: this function writes only caller-owned storage.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_dynamic_channel_info_init(librdp_server_dynamic_channel_info* info);

/**
 * @brief Initialize a server extension event value.
 *
 * @param[out] event Caller-owned event object; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * event is NULL.
 *
 * @note Thread-safety: this function writes only caller-owned storage.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_extension_event_init(librdp_server_extension_event* event);

/**
 * @brief Initialize a server runtime event value.
 *
 * @param[out] event Caller-owned event object; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * event is NULL.
 *
 * @note Thread-safety: this function writes only caller-owned storage.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_event_init(librdp_server_event* event);

/**
 * @brief Initialize a server status snapshot.
 *
 * @param[out] status Caller-owned status object; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * status is NULL.
 *
 * @note Thread-safety: this function writes only caller-owned storage.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_status_init(librdp_server_status* status);

/**
 * @brief Initialize a server metrics snapshot.
 *
 * @param[out] metrics Caller-owned metrics object; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * metrics is NULL.
 *
 * @note Thread-safety: this function writes only caller-owned storage.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_metrics_init(librdp_server_metrics* metrics);

/**
 * @brief Create a server listener object from a versioned config.
 *
 * The config object is borrowed only for the duration of this call; strings
 * are copied. Runtime listener APIs use the returned object in later calls.
 *
 * @param[in] config Initialized config object; must not be NULL.
 *
 * @return Newly allocated server listener owned by the caller, or NULL when
 * config metadata is invalid, a configured limit is invalid, or memory
 * allocation fails.
 *
 * @note Thread-safety: create and free a listener from one serialized context
 * unless the application provides external locking.
 * @since 0.1.0
 */
LIBRDP_API librdp_server* librdp_server_new(const librdp_server_config* config);

/**
 * @brief Close and free a server listener.
 *
 * Passing NULL is allowed. Resources owned by the server object are released.
 *
 * @param[in,out] server Server listener to free, or NULL.
 *
 * @note Thread-safety: the caller must ensure no other thread is using the
 * same listener.
 * @since 0.1.0
 */
LIBRDP_API void librdp_server_free(librdp_server* server);

/**
 * @brief Open the listener socket.
 *
 * The server must be newly created or previously closed. On success,
 * librdp_server_local_port() returns the bound TCP port. This function does
 * not accept peers and does not spawn threads.
 *
 * @param[in,out] server Server listener; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * server; LIBRDP_STATUS_STATE if already listening; LIBRDP_STATUS_IO_ERROR for
 * bind, listen, or socket setup failures.
 *
 * @note Thread-safety: call from the serialized server owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_listen(librdp_server* server);

/**
 * @brief Close the listener socket.
 *
 * The call is idempotent. It does not close peers that were already accepted.
 *
 * @param[in,out] server Server listener; NULL is ignored.
 *
 * @note Thread-safety: call from the serialized server owner context.
 * @since 0.1.0
 */
LIBRDP_API void librdp_server_close(librdp_server* server);

/**
 * @brief Return the bound TCP port for a listening server.
 *
 * @param[in] server Server listener to query, or NULL.
 *
 * @return Bound TCP port, or zero when server is NULL or not listening.
 *
 * @note Thread-safety: read from the serialized server owner context.
 * @since 0.1.0
 */
LIBRDP_API uint16_t librdp_server_local_port(const librdp_server* server);

/**
 * @brief Enable or disable a known optional server feature request.
 *
 * This function records application intent before peers are accepted. The
 * server runtime never advertises a feature unless it can negotiate and route
 * the corresponding server-side path. Feature requests are visible through
 * librdp_server_get_feature_status(), including backend availability at
 * listener scope. Features that require application callbacks become
 * backend-ready only on accepted peers after the relevant callback is installed.
 * Existing peers keep the request set copied when they were accepted.
 *
 * @param[in,out] server Server listener to update; must not be NULL.
 * @param[in] feature Feature bitmask containing only known librdp_feature bits
 * and at least one bit.
 * @param[in] enabled Non-zero to request the feature, zero to clear it.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * server, zero feature, or unknown feature bits; LIBRDP_STATUS_STATE when the
 * listener is already open and peers may inherit inconsistent configuration.
 *
 * @note Thread-safety: call from the serialized server owner context before
 * librdp_server_listen().
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_enable_feature(librdp_server* server,
                                                      librdp_feature feature,
                                                      int enabled);

/**
 * @brief Enable or disable an application-backed provider for server features.
 *
 * Feature providers are the application-owned runtime behind optional server
 * extensions such as clipboard, audio, device redirection, WebAuthn, RAIL,
 * telemetry, and graphics-adjacent virtual channels. Enabling a feature with
 * librdp_server_enable_feature() records negotiation intent; this function
 * separately records that the application can actually serve the requested
 * feature. Side-transport features that are fully handled by the built-in
 * server runtime do not accept providers and return LIBRDP_STATUS_UNSUPPORTED.
 *
 * The provider state controls backend availability in
 * librdp_server_get_feature_status() and is copied into peers accepted after
 * the call. Existing peers are not modified; use
 * librdp_server_peer_enable_feature_provider() for per-peer changes.
 *
 * @param[in,out] server Server listener; must not be NULL.
 * @param[in] feature Bitmask containing only known application-backed
 * librdp_feature bits and at least one bit.
 * @param[in] enabled Non-zero to mark the provider available, zero to clear it.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * server, zero feature, or unknown feature bits; LIBRDP_STATUS_UNSUPPORTED when
 * the mask contains a feature served entirely by the built-in runtime;
 * LIBRDP_STATUS_STATE when the listener is already open and future peers may
 * inherit inconsistent configuration.
 *
 * @note Thread-safety: call from the serialized server owner context before
 * librdp_server_listen().
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_enable_feature_provider(librdp_server* server,
                                                               librdp_feature feature,
                                                               int enabled);

/**
 * @brief Enable or disable a provider for one server extension family.
 *
 * This typed variant records application backend availability for a concrete
 * extension family such as clipboard, printer, USB, WebAuthn, RAIL, CR2, or
 * geometry tracking. The family state is copied into peers accepted after the
 * call. When the family maps to a public librdp_feature, feature-status queries
 * treat the family provider as backend readiness for that feature. Families
 * without a public feature bit remain queryable through
 * librdp_server_get_extension_provider_status().
 *
 * @param[in,out] server Server listener; must not be NULL.
 * @param[in] family Known extension family to update.
 * @param[in] enabled Non-zero to mark the provider available, zero to clear it.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * server or an unknown family; LIBRDP_STATUS_STATE when the listener is already
 * open and future peers could inherit inconsistent state.
 *
 * @note Thread-safety: call from the serialized server owner context before
 * librdp_server_listen().
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_enable_extension_provider(
    librdp_server* server,
    librdp_server_extension_family family,
    int enabled);

/**
 * @brief Query listener-scope provider availability for an extension family.
 *
 * @param[in] server Server listener to query; must not be NULL.
 * @param[in] family Known extension family to query.
 * @param[out] enabled Receives non-zero when the family provider is available;
 * must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * pointers or an unknown family.
 *
 * @note Thread-safety: call from the serialized server owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_get_extension_provider_status(
    const librdp_server* server,
    librdp_server_extension_family family,
    int* enabled);

/**
 * @brief Query local server readiness for one optional feature.
 *
 * The function reports the requested state configured on the server object,
 * whether a server-side runtime is compiled, and whether a listener-scope
 * backend exists. Features that depend on application callbacks report
 * backend_ready as 0 here; use librdp_server_peer_get_feature_status() after
 * accepting a peer and installing callbacks for peer-level backend readiness.
 *
 * @param[in] server Server listener to query; must not be NULL.
 * @param[in] feature Single known librdp_feature value to query; bitmasks with
 * multiple bits, zero, and unknown bits are rejected.
 * @param[out] status Destination status object; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * pointers, zero features, multiple feature bits, or unknown feature bits.
 *
 * @note Thread-safety: call from the serialized server owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_get_feature_status(const librdp_server* server,
                                                          librdp_feature feature,
                                                          librdp_feature_status* status);

/**
 * @brief Return the POSIX poll descriptor for an open listener.
 *
 * Call with fds set to NULL and capacity set to 0 to query the required
 * descriptor count. Applications can poll the returned descriptor and then
 * call librdp_server_accept() with a zero timeout when readable.
 *
 * @param[in] server Listening server; must not be NULL.
 * @param[out] fds Destination array for poll descriptors; may be NULL only
 * when capacity is 0.
 * @param[in] capacity Number of entries available in fds.
 * @param[out] count Required descriptor count; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * server/count or insufficient capacity; LIBRDP_STATUS_STATE when the listener
 * is not open.
 *
 * @note Thread-safety: call from the serialized server owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_get_pollfds(librdp_server* server,
                                                   struct pollfd* fds,
                                                   size_t capacity,
                                                   size_t* count);

/**
 * @brief Accept one pending peer from the listener.
 *
 * The listener must be open. The returned peer owns its socket and must be
 * freed with librdp_server_peer_free(). A timeout returns LIBRDP_STATUS_TIMEOUT
 * without creating a peer.
 *
 * @param[in,out] server Listening server; must not be NULL.
 * @param[in] timeout_ms Poll timeout in milliseconds; must be non-negative.
 * @param[out] peer Destination for the accepted peer; must not be NULL and is
 * set to NULL on timeout or failure.
 *
 * @return LIBRDP_STATUS_OK on accepted peer; LIBRDP_STATUS_TIMEOUT when no
 * peer arrives before timeout; LIBRDP_STATUS_INVALID_ARGUMENT for NULL inputs
 * or negative timeout; LIBRDP_STATUS_STATE when the listener is not open;
 * LIBRDP_STATUS_LIMIT_EXCEEDED when the listener has accepted its configured
 * maximum peer count; LIBRDP_STATUS_IO_ERROR for accept or socket setup
 * failures.
 *
 * @note Thread-safety: call from the serialized server owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_accept(librdp_server* server,
                                              int timeout_ms,
                                              librdp_server_peer** peer);

/**
 * @brief Drive one server-side peer iteration.
 *
 * The current implementation processes the initial TPKT/X.224 connection
 * request and, for Standard RDP requests, validates the following MCS
 * Connect-Initial/GCC Conference Create Request, MCS domain setup, user attach,
 * channel join, Demand Active, and the first activation/data PDUs needed to
 * enter LIBRDP_SERVER_PEER_ACTIVE. The server API owns only protocol
 * orchestration; applications remain responsible for serving graphics,
 * channels, input, and policy on top of the active peer.
 *
 * @param[in,out] peer Peer to drive; must not be NULL.
 * @param[in] timeout_ms Poll timeout in milliseconds; must be non-negative.
 *
 * @return LIBRDP_STATUS_OK when one peer phase was processed or a runtime
 * keepalive/data PDU was accepted; LIBRDP_STATUS_TIMEOUT when no input arrives
 * before timeout; LIBRDP_STATUS_INVALID_ARGUMENT for NULL peer or negative
 * timeout; LIBRDP_STATUS_STATE when the peer is already closed;
 * LIBRDP_STATUS_LIMIT_EXCEEDED when an initial request exceeds the server
 * bound; LIBRDP_STATUS_PROTOCOL_ERROR for malformed input;
 * LIBRDP_STATUS_IO_ERROR for socket failures.
 *
 * @note Thread-safety: call from one serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_run_once(librdp_server_peer* peer, int timeout_ms);

/**
 * @brief Return the POSIX poll descriptor for a server-side peer.
 *
 * The descriptor remains owned by the peer and must not be closed by the
 * caller. Call with fds set to NULL and capacity set to 0 to query the
 * required descriptor count.
 *
 * @param[in] peer Peer to query; must not be NULL.
 * @param[out] fds Destination array for poll descriptors; may be NULL only
 * when capacity is 0.
 * @param[in] capacity Number of entries available in fds.
 * @param[out] count Required descriptor count; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * peer/count or insufficient capacity; LIBRDP_STATUS_STATE when the peer is
 * already closed.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_get_pollfds(librdp_server_peer* peer,
                                                        struct pollfd* fds,
                                                        size_t capacity,
                                                        size_t* count);

/**
 * @brief Notify a peer about poll results collected by the application.
 *
 * Applications that drive their own event loop call
 * librdp_server_peer_get_pollfds(), pass those descriptors to poll(2), copy
 * revents back into the same array, and call this function before
 * librdp_server_peer_dispatch_pending().
 *
 * @param[in,out] peer Peer to notify; must not be NULL.
 * @param[in] fds Descriptor array previously obtained from
 * librdp_server_peer_get_pollfds(); must not be NULL when count is non-zero.
 * @param[in] count Number of descriptors in fds.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * inputs, unknown descriptors, or zero count; LIBRDP_STATUS_STATE when the
 * peer is already closed.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_notify_poll(librdp_server_peer* peer,
                                                        const struct pollfd* fds,
                                                        size_t count);

/**
 * @brief Dispatch peer work made ready by librdp_server_peer_notify_poll().
 *
 * If no readiness is pending, this function returns immediately. Otherwise it
 * processes the same packet path as librdp_server_peer_run_once() without
 * performing another blocking poll.
 *
 * @param[in,out] peer Peer to drive; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success or idle pending state; status values
 * propagated by the peer packet dispatch path on error.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_dispatch_pending(librdp_server_peer* peer);

/**
 * @brief Register the callback for client input and activation control events.
 *
 * Passing NULL disables the callback. user_data is retained but not used until
 * another callback is installed. The callback runs synchronously from
 * librdp_server_peer_run_once().
 *
 * @param[in,out] peer Peer to configure; must not be NULL.
 * @param[in] callback Callback to install, or NULL to clear it.
 * @param[in] user_data Opaque application pointer passed back to callback;
 * may be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * peer is NULL.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_set_input_callback(librdp_server_peer* peer,
                                                               librdp_server_input_callback callback,
                                                               void* user_data);

/**
 * @brief Register the callback for client static virtual-channel payloads.
 *
 * Passing NULL disables the callback. user_data is retained but not used until
 * another callback is installed. The callback runs synchronously from
 * librdp_server_peer_run_once().
 *
 * @param[in,out] peer Peer to configure; must not be NULL.
 * @param[in] callback Callback to install, or NULL to clear it.
 * @param[in] user_data Opaque application pointer passed back to callback;
 * may be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * peer is NULL.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_set_channel_callback(librdp_server_peer* peer,
                                                                 librdp_server_channel_callback callback,
                                                                 void* user_data);

/**
 * @brief Install the dynamic-channel accept policy callback.
 *
 * The callback is optional. When unset, valid client CREATE requests are
 * accepted. When set, it is called before the dynamic channel is added to the
 * peer table. The callback and user_data are borrowed; librdp does not retain
 * ownership of application objects.
 *
 * @param[in,out] peer Peer to configure; must not be NULL.
 * @param[in] callback Optional accept callback, or NULL to restore the default
 * accept-all policy for syntactically valid CREATE requests.
 * @param[in] user_data Opaque application pointer passed to callback; may be
 * NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * peer is NULL.
 *
 * @note Thread-safety: call from the serialized peer owner context. The
 * callback is executed from librdp_server_peer_run_once() on the same thread.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_set_dynamic_channel_accept_callback(
    librdp_server_peer* peer,
    librdp_server_dynamic_channel_accept_callback callback,
    void* user_data);

/**
 * @brief Register the callback for normalized extension-channel events.
 *
 * Passing NULL disables extension delivery. The callback is independent from
 * librdp_server_peer_set_channel_callback(): applications can receive raw
 * channel bytes, normalized extension events, or both.
 *
 * @param[in,out] peer Peer to configure; must not be NULL.
 * @param[in] callback Callback to install, or NULL to clear it.
 * @param[in] user_data Opaque application pointer passed back to callback;
 * may be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * peer is NULL.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_set_extension_callback(librdp_server_peer* peer,
                                                                   librdp_server_extension_callback callback,
                                                                   void* user_data);

/**
 * @brief Register the callback for one normalized extension family.
 *
 * Passing NULL disables the family-specific callback. The callback runs
 * synchronously from librdp_server_peer_run_once() after the outer PDU for the
 * selected family has been validated. It receives the same borrowed event
 * object contract as librdp_server_peer_set_extension_callback(); payload and
 * name pointers are valid only until the callback returns.
 *
 * Family-specific callbacks are independent from the generic extension
 * callback. When both are installed and a matching PDU is valid, the
 * family-specific callback runs first, followed by the generic callback.
 *
 * @param[in,out] peer Peer to configure; must not be NULL.
 * @param[in] family Known extension family to receive; UNKNOWN and values
 * outside librdp_server_extension_family are rejected.
 * @param[in] callback Callback to install, or NULL to clear the family.
 * @param[in] user_data Opaque application pointer passed back to callback;
 * may be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * peer is NULL or family is not a known concrete extension family.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_set_extension_family_callback(
    librdp_server_peer* peer,
    librdp_server_extension_family family,
    librdp_server_extension_callback callback,
    void* user_data);

/**
 * @brief Register the callback for server runtime events.
 *
 * Passing NULL disables the callback. The callback runs synchronously from the
 * public call that changes state, records an error, accepts a surface update,
 * or completes a static-channel join.
 *
 * @param[in,out] peer Peer to configure; must not be NULL.
 * @param[in] callback Callback to install, or NULL to clear it.
 * @param[in] user_data Opaque application pointer passed back to callback;
 * may be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * peer is NULL.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_set_event_callback(librdp_server_peer* peer,
                                                               librdp_server_event_callback callback,
                                                               void* user_data);

/**
 * @brief Enable or disable an application provider for one peer feature.
 *
 * This peer-level override is useful when provider availability is decided only
 * after accepting a connection, for example after authenticating a user or
 * selecting a per-peer backend. It affects only feature status and negotiation
 * readiness for the supplied peer. Payload delivery still uses the registered
 * channel and extension callbacks; this function does not install callbacks
 * and does not take ownership of application objects.
 *
 * @param[in,out] peer Peer to configure; must not be NULL.
 * @param[in] feature Bitmask containing only known application-backed
 * librdp_feature bits and at least one bit.
 * @param[in] enabled Non-zero to mark the provider available, zero to clear it.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * peer, zero feature, or unknown feature bits; LIBRDP_STATUS_UNSUPPORTED when
 * the mask contains a feature served entirely by the built-in runtime;
 * LIBRDP_STATUS_STATE when the peer is closed.
 *
 * @note Thread-safety: call from the serialized peer owner context. This
 * function is not thread-safe against librdp_server_peer_run_once().
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_enable_feature_provider(librdp_server_peer* peer,
                                                                    librdp_feature feature,
                                                                    int enabled);

/**
 * @brief Enable or disable a provider for one accepted peer extension family.
 *
 * The function updates only the supplied peer. It does not install callbacks
 * and does not take ownership of application objects; payload routing continues
 * through the channel and extension callbacks.
 *
 * @param[in,out] peer Peer to configure; must not be NULL.
 * @param[in] family Known extension family to update.
 * @param[in] enabled Non-zero to mark the provider available, zero to clear it.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * peer or an unknown family; LIBRDP_STATUS_STATE when the peer is closed.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_enable_extension_provider(
    librdp_server_peer* peer,
    librdp_server_extension_family family,
    int enabled);

/**
 * @brief Query peer-scope provider availability for an extension family.
 *
 * @param[in] peer Peer to query; must not be NULL.
 * @param[in] family Known extension family to query.
 * @param[out] enabled Receives non-zero when the peer has a provider for the
 * family; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * pointers or an unknown family.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_get_extension_provider_status(
    const librdp_server_peer* peer,
    librdp_server_extension_family family,
    int* enabled);

/**
 * @brief Return the number of static channels advertised by the client.
 *
 * @param[in] peer Peer to query, or NULL.
 *
 * @return Static channel count, or zero when peer is NULL or no client network
 * data has been accepted.
 *
 * @note Thread-safety: read from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API uint32_t librdp_server_peer_static_channel_count(const librdp_server_peer* peer);

/**
 * @brief Return metadata for one advertised static channel.
 *
 * @param[in] peer Peer to query; must not be NULL.
 * @param[in] index Zero-based channel index.
 * @param[out] info Caller-owned metadata output; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * NULL inputs or index outside the advertised channel range.
 *
 * @note Thread-safety: read from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_static_channel_at(const librdp_server_peer* peer,
                                                              uint32_t index,
                                                              librdp_server_static_channel_info* info);

/**
 * @brief Return the number of currently known dynamic virtual channels.
 *
 * @param[in] peer Peer to query, or NULL.
 *
 * @return Number of dynamic channels known to the peer; zero when peer is NULL.
 *
 * @note Thread-safety: read from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API uint32_t librdp_server_peer_dynamic_channel_count(const librdp_server_peer* peer);

/**
 * @brief Copy one dynamic virtual-channel metadata entry.
 *
 * @param[in] peer Peer that owns the DVC table; must not be NULL.
 * @param[in] index Zero-based dynamic-channel table index.
 * @param[out] info Caller-owned metadata object; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * arguments or out-of-range index.
 *
 * @note Thread-safety: read from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_dynamic_channel_at(const librdp_server_peer* peer,
                                                               uint32_t index,
                                                               librdp_server_dynamic_channel_info* info);

/**
 * @brief Query runtime readiness for one optional feature on a peer.
 *
 * The returned status starts from the feature requests copied from the server
 * object at accept time, then adds peer callback availability, peer-observed
 * negotiation, and active state for server runtimes that exist. Unsupported
 * features keep backend_ready, negotiated, and active clear even if the client
 * advertised a related static channel.
 *
 * @param[in] peer Peer to query; must not be NULL.
 * @param[in] feature Single known librdp_feature value to query; bitmasks with
 * multiple bits, zero, and unknown bits are rejected.
 * @param[out] status Destination status object; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * pointers, zero features, multiple feature bits, or unknown feature bits.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_get_feature_status(const librdp_server_peer* peer,
                                                               librdp_feature feature,
                                                               librdp_feature_status* status);

/**
 * @brief Copy server-side peer metrics into caller storage.
 *
 * @param[in] peer Peer to query; must not be NULL.
 * @param[out] metrics Initialized metrics object; must not be NULL and must
 * have valid version and size metadata.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * pointers or invalid metrics metadata.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_get_metrics(const librdp_server_peer* peer,
                                                        librdp_server_metrics* metrics);

/**
 * @brief Reset server-side peer metrics to zero.
 *
 * Version and size metadata are retained in the peer-owned metrics object.
 *
 * @param[in,out] peer Peer whose metrics should be reset; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * peer is NULL.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_reset_metrics(librdp_server_peer* peer);

/**
 * @brief Copy the last recorded peer runtime status.
 *
 * status must be initialized with librdp_server_status_init(). The function
 * copies all fields into caller-owned storage and does not expose borrowed
 * pointers.
 *
 * @param[in] peer Peer to query; must not be NULL.
 * @param[in,out] status Initialized destination status; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * arguments or invalid status metadata.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_get_last_status(const librdp_server_peer* peer,
                                                            librdp_server_status* status);

/**
 * @brief Return the current peer desktop width.
 *
 * The value is initialized from the server configuration and updated after the
 * client core data is accepted during GCC negotiation. Applications should use
 * this value when generating the peer framebuffer because it reflects the
 * negotiated desktop geometry.
 *
 * @param[in] peer Peer to query, or NULL.
 *
 * @return Current peer desktop width in pixels, or zero when peer is NULL.
 *
 * @note Thread-safety: read from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API uint32_t librdp_server_peer_desktop_width(const librdp_server_peer* peer);

/**
 * @brief Return the current peer desktop height.
 *
 * The value is initialized from the server configuration and updated after the
 * client core data is accepted during GCC negotiation. Applications should use
 * this value when generating the peer framebuffer because it reflects the
 * negotiated desktop geometry.
 *
 * @param[in] peer Peer to query, or NULL.
 *
 * @return Current peer desktop height in pixels, or zero when peer is NULL.
 *
 * @note Thread-safety: read from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API uint32_t librdp_server_peer_desktop_height(const librdp_server_peer* peer);

/**
 * @brief Resize the server-side desktop surface.
 *
 * The peer stores a BGRA32 framebuffer with the requested dimensions. When the
 * peer is already active, the function starts a reactivation by sending a new
 * Demand Active PDU; the application should continue driving the peer until it
 * returns to ACTIVE.
 *
 * @param[in,out] peer Peer to resize; must not be NULL.
 * @param[in] width New desktop width in pixels; must be non-zero.
 * @param[in] height New desktop height in pixels; must be non-zero.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * NULL peer or invalid dimensions; LIBRDP_STATUS_NO_MEMORY on allocation
 * failure; transport errors if reactivation cannot be sent.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_surface_resize(librdp_server_peer* peer,
                                                           uint32_t width,
                                                           uint32_t height);

/**
 * @brief Copy BGRA32 pixels into the peer surface.
 *
 * pixels is borrowed only for the duration of the call. The rectangle must fit
 * inside the current peer surface. This function updates the stored server
 * surface but does not force an immediate network send; call
 * librdp_server_peer_surface_present() to send a dirty rectangle.
 *
 * @param[in,out] peer Peer whose surface receives pixels; must not be NULL.
 * @param[in] x Destination x coordinate.
 * @param[in] y Destination y coordinate.
 * @param[in] width Rectangle width; must be non-zero.
 * @param[in] height Rectangle height; must be non-zero.
 * @param[in] stride Source row stride in bytes; must cover width * 4 bytes.
 * @param[in] pixels Borrowed BGRA32 pixels; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * invalid arguments or out-of-bounds rectangles; LIBRDP_STATUS_NO_MEMORY when
 * the surface cannot be allocated.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_surface_blit_bgra32(librdp_server_peer* peer,
                                                                uint32_t x,
                                                                uint32_t y,
                                                                uint32_t width,
                                                                uint32_t height,
                                                                size_t stride,
                                                                const uint8_t* pixels);

/**
 * @brief Send one dirty rectangle from the stored peer surface.
 *
 * The peer must be ACTIVE and output must not be suppressed. The rectangle is
 * serialized as an uncompressed 32-bpp bitmap update.
 *
 * @param[in,out] peer Peer that owns the surface; must not be NULL.
 * @param[in] x Dirty rectangle x coordinate.
 * @param[in] y Dirty rectangle y coordinate.
 * @param[in] width Dirty rectangle width; must be non-zero.
 * @param[in] height Dirty rectangle height; must be non-zero.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * invalid arguments or out-of-bounds rectangles; LIBRDP_STATUS_STATE when the
 * peer is not ACTIVE or output is suppressed; LIBRDP_STATUS_NO_MEMORY for
 * temporary buffer allocation failure; transport errors for send failures.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_surface_present(librdp_server_peer* peer,
                                                            uint32_t x,
                                                            uint32_t y,
                                                            uint32_t width,
                                                            uint32_t height);

/**
 * @brief Send data on a joined client-advertised static channel.
 *
 * data is borrowed only for the duration of the call and is copied into the
 * wire buffer before the function returns.
 *
 * @param[in,out] peer Peer that owns the channel; must not be NULL.
 * @param[in] channel_id Joined static channel identifier.
 * @param[in] data Borrowed channel bytes; may be NULL only when data_len is 0.
 * @param[in] data_len Number of bytes to send.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * peer, unknown channel, or invalid payload; LIBRDP_STATUS_STATE when the peer
 * is not ACTIVE; LIBRDP_STATUS_LIMIT_EXCEEDED when the payload is too large;
 * transport errors for send failures.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_channel_data(librdp_server_peer* peer,
                                                              uint16_t channel_id,
                                                              const void* data,
                                                              size_t data_len);

/**
 * @brief Request creation of a dynamic virtual channel from the server side.
 *
 * The peer must be ACTIVE, the client must have joined the `drdynvc` static
 * channel, and the DVC capability exchange must have completed. The call sends
 * a CREATE request and records a pending channel; the channel becomes visible
 * through librdp_server_peer_dynamic_channel_count() only after the client
 * replies with success. The channel name is copied and must contain printable
 * non-space ASCII bytes that fit in librdp_server_dynamic_channel_info::name.
 *
 * @param[in,out] peer Peer that owns the dynamic channel table; must not be
 * NULL.
 * @param[in] dynamic_channel_id Application-selected DVC identifier; must be
 * non-zero and must not already be open or pending on this peer.
 * @param[in] priority DVC priority encoded in the CREATE header.
 * @param[in] name NUL-terminated DVC name; must not be NULL. The string is
 * copied before the call returns.
 *
 * @return LIBRDP_STATUS_OK after the CREATE request is sent;
 * LIBRDP_STATUS_INVALID_ARGUMENT for NULL peer/name, invalid channel id,
 * duplicate id, invalid priority, or invalid name; LIBRDP_STATUS_STATE when
 * the peer is not ACTIVE or DVC is not negotiated; LIBRDP_STATUS_LIMIT_EXCEEDED
 * when the peer channel table is full; transport errors for send failures.
 *
 * @note Thread-safety: call from the serialized peer owner context. Channel
 * lifecycle callbacks are delivered later from the same dispatch context when
 * the client accepts or closes the channel.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_open_dynamic_channel(librdp_server_peer* peer,
                                                                 uint32_t dynamic_channel_id,
                                                                 uint8_t priority,
                                                                 const char* name);

/**
 * @brief Send data on an open dynamic virtual channel.
 *
 * data is borrowed only for the call duration and copied into a drdynvc packet
 * before the function returns. Large payloads are fragmented.
 *
 * @param[in,out] peer Peer that owns the dynamic channel; must not be NULL.
 * @param[in] dynamic_channel_id Open dynamic channel identifier.
 * @param[in] data Borrowed payload bytes; may be NULL only when data_len is 0.
 * @param[in] data_len Number of bytes to send.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * peer, unknown/closed channel, or invalid payload; LIBRDP_STATUS_STATE when
 * the peer is not ACTIVE; LIBRDP_STATUS_LIMIT_EXCEEDED when the payload exceeds
 * the server DVC limit; transport errors for send failures.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_dynamic_channel_data(librdp_server_peer* peer,
                                                                      uint32_t dynamic_channel_id,
                                                                      const void* data,
                                                                      size_t data_len);

/**
 * @brief Process one UDP2 side-transport datagram for an active peer.
 *
 * The application owns the UDP socket or gateway tunnel and passes each
 * received UDP2 datagram to this function after multitransport negotiation.
 * The datagram is validated, decoded, and, when it carries data, acknowledged
 * into the caller-provided response buffer. The response buffer remains
 * caller-owned and response_len receives either the number of bytes written or
 * the required size when the buffer is too small.
 *
 * @param[in,out] peer Active peer that negotiated multitransport; must not be
 * NULL.
 * @param[in] datagram Borrowed UDP2 wire datagram; must not be NULL.
 * @param[in] datagram_len Number of bytes in datagram; must be non-zero.
 * @param[out] response Caller-owned response buffer. May be NULL only when
 * response_capacity is zero; in that case data packets report the required
 * size through response_len and return LIBRDP_STATUS_LIMIT_EXCEEDED.
 * @param[in] response_capacity Number of bytes available in response.
 * @param[out] response_len Number of response bytes written, or required bytes
 * when the response buffer is too small; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK when the datagram is accepted;
 * LIBRDP_STATUS_INVALID_ARGUMENT for NULL pointers, empty datagrams, or an
 * inconsistent response buffer; LIBRDP_STATUS_STATE when the peer is not
 * ACTIVE; LIBRDP_STATUS_UNSUPPORTED when UDP2 was not requested or
 * multitransport was not negotiated; LIBRDP_STATUS_LIMIT_EXCEEDED when the
 * response buffer is too small; LIBRDP_STATUS_PROTOCOL_ERROR for malformed
 * UDP2 datagrams; allocation errors if temporary buffers cannot be grown.
 *
 * @note Thread-safety: call from the serialized peer owner context. This API
 * does not create sockets or threads.
 * @warning UDP2 data payloads can contain redirected channel traffic. Keep
 * traces redacted and avoid logging datagram bodies outside librdp.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_process_udp2_datagram(librdp_server_peer* peer,
                                                                  const void* datagram,
                                                                  size_t datagram_len,
                                                                  void* response,
                                                                  size_t response_capacity,
                                                                  size_t* response_len);

/**
 * @brief Send a validated payload on a joined static extension channel.
 *
 * The helper checks that channel_id names the expected extension family and
 * validates the outer PDU for known protocols before writing it to the peer.
 * payload is borrowed only for the duration of the call.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] family Expected extension family for the static channel.
 * @param[in] channel_id Joined static channel identifier.
 * @param[in] payload Borrowed extension payload bytes; may be NULL only when
 * payload_len is zero.
 * @param[in] payload_len Number of bytes in payload.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * NULL pointers, a non-static family, or family/channel mismatch;
 * LIBRDP_STATUS_PROTOCOL_ERROR for malformed payload; LIBRDP_STATUS_STATE
 * when the peer is not ACTIVE; transport errors from the underlying send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_static_extension_data(
    librdp_server_peer* peer,
    librdp_server_extension_family family,
    uint16_t channel_id,
    const void* payload,
    size_t payload_len);

/**
 * @brief Send a validated payload on an open dynamic extension channel.
 *
 * The helper checks that dynamic_channel_id is currently open with the
 * expected extension family and validates the outer PDU for known protocols
 * before writing it to the peer. payload is borrowed only for the duration of
 * the call.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] family Expected extension family for the dynamic channel.
 * @param[in] dynamic_channel_id Open dynamic channel identifier.
 * @param[in] payload Borrowed extension payload bytes; may be NULL only when
 * payload_len is zero.
 * @param[in] payload_len Number of bytes in payload.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * NULL pointers, a non-dynamic family, or family/channel mismatch;
 * LIBRDP_STATUS_PROTOCOL_ERROR for malformed payload; LIBRDP_STATUS_STATE
 * when the peer is not ACTIVE; transport errors from the underlying send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_dynamic_extension_data(
    librdp_server_peer* peer,
    librdp_server_extension_family family,
    uint32_t dynamic_channel_id,
    const void* payload,
    size_t payload_len);

/**
 * @brief Initialize a server extension runtime state snapshot.
 *
 * @param[out] state Destination structure; must not be NULL. The function
 * clears all fields, sets size to sizeof(*state), sets version to the current
 * structure version, and sets last_status to LIBRDP_STATUS_OK.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a NULL
 * state pointer.
 *
 * @note Thread-safety: independent of any server object.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_extension_state_init(librdp_server_extension_state* state);

/**
 * @brief Query server-side runtime state for one extension family.
 *
 * The returned snapshot is copied from peer-owned state and remains valid after
 * the call returns. Payload data is never included. provider_ready is derived
 * from the peer provider mask at query time, so it reflects the current
 * application registration state.
 *
 * @param[in] peer Peer to query; must not be NULL.
 * @param[in] family Extension family to query; must be a known family.
 * @param[out] state Destination snapshot; must not be NULL and must have been
 * initialized with librdp_server_extension_state_init().
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * pointers, unknown families, or incompatible state structures.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_get_extension_state(
    const librdp_server_peer* peer,
    librdp_server_extension_family family,
    librdp_server_extension_state* state);

/**
 * @brief Cancel pending server work for one extension family.
 *
 * The function clears family-level pending request/open/closing state and marks
 * the runtime snapshot as cancelled. It does not synthesize protocol payloads and
 * does not close unrelated channels; protocol close helpers remain explicit.
 *
 * @param[in,out] peer Peer whose extension state is updated; must not be NULL.
 * @param[in] family Extension family to cancel; must be known.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a NULL
 * peer or unknown family; LIBRDP_STATUS_STATE when the peer is closed.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_cancel_extension(
    librdp_server_peer* peer,
    librdp_server_extension_family family);

/**
 * @brief Record a timeout for one server extension family.
 *
 * Applications use this when an application-owned provider times out while
 * handling a server extension request. The function updates only runtime state
 * and metrics; it does not close channels and does not send protocol PDUs.
 *
 * @param[in,out] peer Peer whose extension state is updated; must not be NULL.
 * @param[in] family Extension family that timed out; must be known.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a NULL
 * peer or unknown family; LIBRDP_STATUS_STATE when the peer is closed.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_record_extension_timeout(
    librdp_server_peer* peer,
    librdp_server_extension_family family);

/**
 * @brief Send a typed device-redirection device reply.
 *
 * The helper validates that device_id is known for family before serializing the
 * rdpdr Device Reply PDU on the joined device-redirection channel.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] channel_id Joined device-redirection static channel identifier.
 * @param[in] family Expected device family: filesystem, printer, smartcard,
 * serial port, or parallel port.
 * @param[in] device_id Device identifier announced by the client.
 * @param[in] result_code Device acceptance status to send.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * invalid family, unknown device, family mismatch, or non-rdpdr channel;
 * LIBRDP_STATUS_STATE when the peer is not ACTIVE; transport or allocation
 * errors from the send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_device_reply(
    librdp_server_peer* peer,
    uint16_t channel_id,
    librdp_server_extension_family family,
    uint32_t device_id,
    uint32_t result_code);

/**
 * @brief Send a typed device-redirection IO completion.
 *
 * The helper validates that device_id belongs to family and serializes one rdpdr
 * IO Completion PDU. payload is borrowed only for the duration of the call and
 * may be NULL only when payload_len is zero.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] channel_id Joined device-redirection static channel identifier.
 * @param[in] family Expected device family: filesystem, printer, smartcard,
 * serial port, or parallel port.
 * @param[in] device_id Device identifier announced by the client.
 * @param[in] completion_id Completion identifier from the matching IO request.
 * @param[in] io_status Protocol status value to return.
 * @param[in] payload Optional borrowed completion payload; may be NULL only when
 * payload_len is zero.
 * @param[in] payload_len Number of bytes in payload.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * invalid family, unknown device, family mismatch, invalid payload, or non-rdpdr
 * channel; LIBRDP_STATUS_STATE when the peer is not ACTIVE; transport or
 * allocation errors from the send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @warning Completion payloads can contain file data, APDUs, or device data and
 * remain redacted by default trace policy.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_device_io_completion(
    librdp_server_peer* peer,
    uint16_t channel_id,
    librdp_server_extension_family family,
    uint32_t device_id,
    uint32_t completion_id,
    uint32_t io_status,
    const void* payload,
    size_t payload_len);

/**
 * @brief Initialize a server clipboard state snapshot.
 *
 * @param[out] state Destination structure; must not be NULL. The function
 * clears all fields, sets size to sizeof(*state), and sets version to the
 * current structure version.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a
 * NULL state pointer.
 *
 * @note Thread-safety: independent of any server object.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_clipboard_state_init(librdp_server_clipboard_state* state);

/**
 * @brief Query server-side clipboard runtime state for a peer.
 *
 * The returned snapshot contains state flags and request identifiers only. It
 * does not expose clipboard payload bytes, filenames, or format-name strings.
 *
 * @param[in] peer Peer to query; must not be NULL.
 * @param[out] state Destination snapshot; must not be NULL and must have been
 * initialized with librdp_server_clipboard_state_init().
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * NULL pointers or an incompatible state structure.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_get_clipboard_state(
    const librdp_server_peer* peer,
    librdp_server_clipboard_state* state);

/**
 * @brief Cancel pending server clipboard requests tracked for a peer.
 *
 * The function clears server-side format-data and file-contents request
 * correlation state. It does not send a protocol PDU and does not discard
 * clipboard payload data because the server does not retain payload bytes.
 *
 * @param[in,out] peer Peer whose pending clipboard request state is cleared;
 * must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a
 * NULL peer; LIBRDP_STATUS_STATE when the peer is already closed.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_cancel_clipboard_requests(librdp_server_peer* peer);

/**
 * @brief Send a clipboard Monitor Ready PDU on a joined clipboard channel.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] channel_id Joined static clipboard channel identifier.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a
 * NULL peer or non-clipboard channel; LIBRDP_STATUS_STATE when the peer is not
 * ACTIVE; transport or allocation errors from the underlying send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_clipboard_monitor_ready(librdp_server_peer* peer,
                                                                         uint16_t channel_id);

/**
 * @brief Send clipboard general capabilities on a joined clipboard channel.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] channel_id Joined static clipboard channel identifier.
 * @param[in] general_flags Clipboard general capability flags.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a
 * NULL peer or non-clipboard channel; LIBRDP_STATUS_STATE when the peer is not
 * ACTIVE; transport or allocation errors from the underlying send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_clipboard_capabilities(librdp_server_peer* peer,
                                                                        uint16_t channel_id,
                                                                        uint32_t general_flags);

/**
 * @brief Send a clipboard format list on a joined clipboard channel.
 *
 * formats is borrowed for the duration of the call. Each entry name is
 * borrowed and may be NULL only when name_len is zero. long_names selects the
 * wire encoding expected by the peer: non-zero for UTF-16LE format names, zero
 * for legacy ASCII names.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] channel_id Joined static clipboard channel identifier.
 * @param[in] formats Borrowed array of format entries; may be NULL only when
 * count is zero.
 * @param[in] count Number of entries in formats.
 * @param[in] long_names Non-zero to encode long UTF-16LE names; zero for ASCII
 * names.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * invalid arguments or a non-clipboard channel; LIBRDP_STATUS_LIMIT_EXCEEDED
 * for excessive format counts or encoded payloads; LIBRDP_STATUS_STATE when
 * the peer is not ACTIVE; transport or allocation errors from the underlying
 * send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @warning Format names may contain user data; avoid passing sensitive names
 * when trace unsafe payload mode is enabled.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_clipboard_format_list(
    librdp_server_peer* peer,
    uint16_t channel_id,
    const librdp_server_clipboard_format* formats,
    uint32_t count,
    int long_names);

/**
 * @brief Send a clipboard format-list response on a joined clipboard channel.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] channel_id Joined static clipboard channel identifier.
 * @param[in] ok Non-zero sends success; zero sends failure.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a
 * NULL peer or non-clipboard channel; LIBRDP_STATUS_STATE when the peer is not
 * ACTIVE; transport or allocation errors from the underlying send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_clipboard_format_list_response(librdp_server_peer* peer,
                                                                               uint16_t channel_id,
                                                                               int ok);

/**
 * @brief Send a clipboard format-data request on a joined clipboard channel.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] channel_id Joined static clipboard channel identifier.
 * @param[in] format_id Clipboard format identifier to request.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a
 * NULL peer or non-clipboard channel; LIBRDP_STATUS_STATE when the peer is not
 * ACTIVE; transport or allocation errors from the underlying send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_clipboard_format_data_request(librdp_server_peer* peer,
                                                                              uint16_t channel_id,
                                                                              uint32_t format_id);

/**
 * @brief Send a clipboard format-data response on a joined clipboard channel.
 *
 * data is borrowed only for the duration of the call and may be NULL only when
 * data_len is zero. Failed responses must use ok equal to zero and data_len
 * equal to zero.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] channel_id Joined static clipboard channel identifier.
 * @param[in] ok Non-zero sends success; zero sends failure.
 * @param[in] data Borrowed response bytes; may be NULL only when data_len is
 * zero.
 * @param[in] data_len Number of bytes in data.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * invalid arguments or a non-clipboard channel; LIBRDP_STATUS_STATE when the
 * peer is not ACTIVE; transport or allocation errors from the underlying send
 * path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @warning Clipboard data can contain sensitive user content and is redacted
 * by default trace policy.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_clipboard_format_data_response(librdp_server_peer* peer,
                                                                               uint16_t channel_id,
                                                                               int ok,
                                                                               const void* data,
                                                                               size_t data_len);

/**
 * @brief Send a clipboard file-contents request on a joined clipboard channel.
 *
 * clip_data_id is optional and borrowed only for the duration of the call.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] channel_id Joined static clipboard channel identifier.
 * @param[in] stream_id Request correlation identifier.
 * @param[in] lindex File-list index requested from the peer.
 * @param[in] flags File contents request flags.
 * @param[in] position Byte offset for range requests.
 * @param[in] requested Requested byte count.
 * @param[in] clip_data_id Optional clipboard lock identifier; may be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * invalid arguments or a non-clipboard channel; LIBRDP_STATUS_STATE when the
 * peer is not ACTIVE; transport or allocation errors from the underlying send
 * path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_clipboard_file_contents_request(
    librdp_server_peer* peer,
    uint16_t channel_id,
    uint32_t stream_id,
    int32_t lindex,
    uint32_t flags,
    uint64_t position,
    uint32_t requested,
    const uint32_t* clip_data_id);

/**
 * @brief Send a clipboard file-contents response on a joined clipboard channel.
 *
 * data is borrowed only for the duration of the call and may be NULL only when
 * data_len is zero. Failed responses must use ok equal to zero and data_len
 * equal to zero.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] channel_id Joined static clipboard channel identifier.
 * @param[in] ok Non-zero sends success; zero sends failure.
 * @param[in] stream_id Request correlation identifier.
 * @param[in] data Borrowed response bytes; may be NULL only when data_len is
 * zero.
 * @param[in] data_len Number of bytes in data.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * invalid arguments or a non-clipboard channel; LIBRDP_STATUS_STATE when the
 * peer is not ACTIVE; transport or allocation errors from the underlying send
 * path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @warning File clipboard data can contain sensitive user content and is
 * redacted by default trace policy.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_clipboard_file_contents_response(
    librdp_server_peer* peer,
    uint16_t channel_id,
    int ok,
    uint32_t stream_id,
    const void* data,
    size_t data_len);

/**
 * @brief Send a clipboard lock PDU on a joined clipboard channel.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] channel_id Joined static clipboard channel identifier.
 * @param[in] clip_data_id Clipboard data identifier to lock.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a
 * NULL peer or non-clipboard channel; LIBRDP_STATUS_STATE when the peer is not
 * ACTIVE; transport or allocation errors from the underlying send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_clipboard_lock(librdp_server_peer* peer,
                                                                uint16_t channel_id,
                                                                uint32_t clip_data_id);

/**
 * @brief Send a clipboard unlock PDU on a joined clipboard channel.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] channel_id Joined static clipboard channel identifier.
 * @param[in] clip_data_id Clipboard data identifier to unlock.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a
 * NULL peer or non-clipboard channel; LIBRDP_STATUS_STATE when the peer is not
 * ACTIVE; transport or allocation errors from the underlying send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_clipboard_unlock(librdp_server_peer* peer,
                                                                  uint16_t channel_id,
                                                                  uint32_t clip_data_id);

/**
 * @brief Send an Echo response on an open ECHO dynamic channel.
 *
 * payload is borrowed only for the duration of the call and may be NULL only
 * when payload_len is zero.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] dynamic_channel_id Open ECHO dynamic channel identifier.
 * @param[in] payload Borrowed response payload bytes; may be NULL only when
 * payload_len is zero.
 * @param[in] payload_len Number of bytes in payload.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * invalid arguments or a non-ECHO channel; LIBRDP_STATUS_STATE when the peer is
 * not ACTIVE; LIBRDP_STATUS_LIMIT_EXCEEDED for oversized Echo payloads;
 * transport errors from the underlying send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_echo_response(librdp_server_peer* peer,
                                                               uint32_t dynamic_channel_id,
                                                               const void* payload,
                                                               size_t payload_len);

/**
 * @brief Send a single-monitor Display Control layout on an open channel.
 *
 * The helper creates a validated single primary monitor layout from width and
 * height before serializing it.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] dynamic_channel_id Open Display Control dynamic channel id.
 * @param[in] width Requested monitor width in pixels.
 * @param[in] height Requested monitor height in pixels.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * invalid geometry or a non-Display-Control channel; LIBRDP_STATUS_STATE when
 * the peer is not ACTIVE; transport or allocation errors from the send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_display_single_monitor_layout(librdp_server_peer* peer,
                                                                               uint32_t dynamic_channel_id,
                                                                               uint32_t width,
                                                                               uint32_t height);

/**
 * @brief Send default RDP Graphics Pipeline capabilities.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] dynamic_channel_id Open Graphics Pipeline dynamic channel id.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a
 * NULL peer or non-graphics channel; LIBRDP_STATUS_STATE when the peer is not
 * ACTIVE; transport or allocation errors from the send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_graphics_default_caps(librdp_server_peer* peer,
                                                                       uint32_t dynamic_channel_id);

/**
 * @brief Send a BGRA32 bitmap update through the RDP Graphics Pipeline.
 *
 * The helper packs the supplied BGRA32 rows into an uncompressed
 * Wire-to-Surface command. The caller owns pixels and may release or reuse the
 * buffer after the function returns.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] dynamic_channel_id Open Graphics Pipeline dynamic channel id.
 * @param[in] surface_id Destination graphics surface identifier.
 * @param[in] x Destination left coordinate in the surface.
 * @param[in] y Destination top coordinate in the surface.
 * @param[in] width Bitmap width in pixels; must be non-zero and fit the
 * 16-bit RDPGFX rectangle range together with x.
 * @param[in] height Bitmap height in pixels; must be non-zero and fit the
 * 16-bit RDPGFX rectangle range together with y.
 * @param[in] stride Source row stride in bytes; must be at least
 * width * 4.
 * @param[in] pixels Source BGRA32 rows; must not be NULL. The buffer is
 * borrowed for the duration of the call only and is copied into the outgoing
 * PDU before return.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * invalid geometry, stride, NULL pointers, or a non-graphics channel;
 * LIBRDP_STATUS_LIMIT_EXCEEDED when the packed bitmap exceeds the RDPGFX PDU
 * size range; LIBRDP_STATUS_STATE when the peer is not ACTIVE; transport or
 * allocation errors from the send path.
 *
 * @note This function intentionally sends only the uncompressed RDPGFX bitmap
 * path. Compressed server codecs require a registered encoder path before they
 * are advertised.
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_graphics_bitmap_bgra32(librdp_server_peer* peer,
                                                                        uint32_t dynamic_channel_id,
                                                                        uint16_t surface_id,
                                                                        uint32_t x,
                                                                        uint32_t y,
                                                                        uint32_t width,
                                                                        uint32_t height,
                                                                        uint32_t stride,
                                                                        const void* pixels);

/**
 * @brief Send an RDP Graphics Pipeline Create Surface command.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] dynamic_channel_id Open Graphics Pipeline dynamic channel id.
 * @param[in] surface_id Graphics surface identifier.
 * @param[in] width Surface width in pixels.
 * @param[in] height Surface height in pixels.
 * @param[in] pixel_format RDPGFX pixel format byte.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * invalid arguments or a non-graphics channel; LIBRDP_STATUS_STATE when the
 * peer is not ACTIVE; transport or allocation errors from the send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_graphics_create_surface(librdp_server_peer* peer,
                                                                         uint32_t dynamic_channel_id,
                                                                         uint16_t surface_id,
                                                                         uint16_t width,
                                                                         uint16_t height,
                                                                         uint8_t pixel_format);

/**
 * @brief Send an RDP Graphics Pipeline Delete Surface command.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] dynamic_channel_id Open Graphics Pipeline dynamic channel id.
 * @param[in] surface_id Graphics surface identifier.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a
 * NULL peer or non-graphics channel; LIBRDP_STATUS_STATE when the peer is not
 * ACTIVE; transport or allocation errors from the send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_graphics_delete_surface(librdp_server_peer* peer,
                                                                         uint32_t dynamic_channel_id,
                                                                         uint16_t surface_id);

/**
 * @brief Send an RDP Graphics Pipeline Reset Graphics command.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] dynamic_channel_id Open Graphics Pipeline dynamic channel id.
 * @param[in] width Desktop width in pixels.
 * @param[in] height Desktop height in pixels.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * invalid arguments or a non-graphics channel; LIBRDP_STATUS_STATE when the
 * peer is not ACTIVE; transport or allocation errors from the send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_graphics_reset(librdp_server_peer* peer,
                                                                uint32_t dynamic_channel_id,
                                                                uint32_t width,
                                                                uint32_t height);

/**
 * @brief Configure the maximum number of unacknowledged GFX frames.
 *
 * The limit is stored on the peer and is enforced by
 * librdp_server_peer_send_graphics_start_frame(). It controls server-side
 * backpressure only; it does not change any wire capability advertised to the
 * client.
 *
 * @param[in,out] peer Accepted server peer; must not be NULL.
 * @param[in] frame_limit Maximum pending frame count. Must be in the supported
 * implementation range and must not be lower than the current pending count.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a
 * NULL peer or unsupported limit; LIBRDP_STATUS_STATE when the current pending
 * frame count is already above frame_limit.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_set_graphics_frame_queue_limit(librdp_server_peer* peer,
                                                                           uint32_t frame_limit);

/**
 * @brief Query server-side GFX frame acknowledgement state.
 *
 * Any output pointer may be NULL. The values are snapshots of the peer-owned
 * state and remain valid only for the duration of the call.
 *
 * @param[in] peer Accepted server peer; must not be NULL.
 * @param[out] pending_frames Optional destination for the number of frames
 * sent with End Frame and not yet acknowledged by the client; may be NULL to
 * skip this value.
 * @param[out] frame_limit Optional destination for the active queue limit; may
 * be NULL to skip this value.
 * @param[out] last_ack_frame_id Optional destination for the latest client
 * Frame Acknowledge frame identifier accepted by the server; may be NULL to
 * skip this value.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a
 * NULL peer.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_get_graphics_frame_state(const librdp_server_peer* peer,
                                                                     uint32_t* pending_frames,
                                                                     uint32_t* frame_limit,
                                                                     uint32_t* last_ack_frame_id);

/**
 * @brief Send an RDP Graphics Pipeline Start Frame command.
 *
 * The server generates a monotonic frame identifier and stores it in frame_id
 * after the command has been written successfully. A frame must be completed
 * with librdp_server_peer_send_graphics_end_frame() before another frame can be
 * started.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] dynamic_channel_id Open Graphics Pipeline dynamic channel id.
 * @param[in] timestamp Server timestamp value to place in the Start Frame PDU.
 * @param[out] frame_id Destination for the generated frame identifier; must
 * not be NULL. It is set to zero before the send attempt and populated only on
 * success.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a
 * NULL peer, NULL frame_id, or non-graphics channel;
 * LIBRDP_STATUS_LIMIT_EXCEEDED when the configured queue limit would be
 * exceeded; LIBRDP_STATUS_STATE when the peer is not ACTIVE or another frame
 * is already open; transport or allocation errors from the send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_graphics_start_frame(librdp_server_peer* peer,
                                                                      uint32_t dynamic_channel_id,
                                                                      uint32_t timestamp,
                                                                      uint32_t* frame_id);

/**
 * @brief Send an RDP Graphics Pipeline End Frame command.
 *
 * The frame_id must be the identifier returned by the currently open
 * librdp_server_peer_send_graphics_start_frame() call. On success the frame is
 * counted as pending until a client Frame Acknowledge PDU advances past it.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] dynamic_channel_id Open Graphics Pipeline dynamic channel id.
 * @param[in] frame_id Frame identifier returned by the matching Start Frame.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a
 * NULL peer, zero frame_id, or non-graphics channel; LIBRDP_STATUS_STATE when
 * the peer is not ACTIVE or frame_id does not match the currently open frame;
 * transport or allocation errors from the send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_graphics_end_frame(librdp_server_peer* peer,
                                                                    uint32_t dynamic_channel_id,
                                                                    uint32_t frame_id);

/**
 * @brief Send a Core Input initialization request.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] dynamic_channel_id Open Core Input dynamic channel id.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a
 * NULL peer or non-Core-Input channel; LIBRDP_STATUS_STATE when the peer is
 * not ACTIVE; transport or allocation errors from the send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_core_input_init(librdp_server_peer* peer,
                                                                 uint32_t dynamic_channel_id);

/**
 * @brief Send an RDPEI server-ready message for touch and pen input.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] dynamic_channel_id Open RDPEI dynamic channel id.
 * @param[in] protocol_version RDPEI protocol version advertised by the server.
 * @param[in] supported_features Optional supported feature flags.
 * @param[in] has_supported_features Non-zero to include supported_features.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a
 * NULL peer or non-RDPEI channel; LIBRDP_STATUS_STATE when the peer is not
 * ACTIVE; transport or allocation errors from the send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_touch_ready(librdp_server_peer* peer,
                                                             uint32_t dynamic_channel_id,
                                                             uint32_t protocol_version,
                                                             uint32_t supported_features,
                                                             int has_supported_features);

/**
 * @brief Send Mouse Cursor channel capabilities.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] dynamic_channel_id Open Mouse Cursor dynamic channel id.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a
 * NULL peer or non-Mouse-Cursor channel; LIBRDP_STATUS_STATE when the peer is
 * not ACTIVE; transport or allocation errors from the send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_mouse_cursor_caps(librdp_server_peer* peer,
                                                                   uint32_t dynamic_channel_id);

/**
 * @brief Send a video geometry update on the joined TSMF static channel.
 *
 * The helper serializes one geometry update for an existing presentation. The
 * geometry and visible-rectangle buffers are borrowed only for the duration of
 * the call and are validated by the channel encoder before any bytes are sent.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] channel_id Joined TSMF static channel identifier.
 * @param[in] message_id Protocol message identifier for request correlation.
 * @param[in] presentation_id Presentation GUID; must point to 16 bytes and
 * must not be NULL.
 * @param[in] geometry Borrowed geometry-info bytes; may be NULL only when
 * geometry_len is zero.
 * @param[in] geometry_len Number of bytes in geometry.
 * @param[in] visible_rect Borrowed visible-rectangle bytes; may be NULL only
 * when visible_rect_len is zero.
 * @param[in] visible_rect_len Number of bytes in visible_rect.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for a
 * NULL peer, NULL presentation_id, invalid borrowed buffers, or a non-TSMF
 * channel; LIBRDP_STATUS_STATE when the peer is not ACTIVE; transport or
 * allocation errors from the send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_video_geometry_update(librdp_server_peer* peer,
                                                                       uint16_t channel_id,
                                                                       uint32_t message_id,
                                                                       const uint8_t presentation_id[16],
                                                                       const void* geometry,
                                                                       uint32_t geometry_len,
                                                                       const void* visible_rect,
                                                                       uint32_t visible_rect_len);

/**
 * @brief Send telemetry timing metrics on an open telemetry dynamic channel.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] dynamic_channel_id Open telemetry dynamic channel identifier.
 * @param[in] prompt_for_credentials_ms Elapsed milliseconds before credential
 * prompt.
 * @param[in] authentication_ms Elapsed milliseconds for authentication.
 * @param[in] desktop_ready_ms Elapsed milliseconds before desktop readiness.
 * @param[in] first_graphics_received_ms Elapsed milliseconds before first
 * graphics update.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * invalid arguments or a non-telemetry channel; LIBRDP_STATUS_STATE when the
 * peer is not ACTIVE; transport errors from the send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_telemetry_metrics(
    librdp_server_peer* peer,
    uint32_t dynamic_channel_id,
    uint32_t prompt_for_credentials_ms,
    uint32_t authentication_ms,
    uint32_t desktop_ready_ms,
    uint32_t first_graphics_received_ms);

/**
 * @brief Send a multiparty filter-state update on a joined multiparty channel.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 * @param[in] channel_id Joined static multiparty channel identifier.
 * @param[in] filter_state Multiparty filter state value to encode.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for
 * invalid arguments or a non-multiparty channel; LIBRDP_STATUS_STATE when the
 * peer is not ACTIVE; transport errors from the send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_multiparty_filter_state(librdp_server_peer* peer,
                                                                         uint16_t channel_id,
                                                                         uint8_t filter_state);

/**
 * @brief Send the Desktop Composition alternate-secondary start order.
 *
 * The order is delivered on the negotiated global slow-path update stream, not
 * on a virtual channel. Applications call this after activation when they have
 * enabled LIBRDP_FEATURE_DESKTOP_COMPOSITION and want the peer to enter the
 * desktop-composition drawing path supported by the server runtime.
 *
 * @param[in,out] peer Active peer; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * peer is NULL; LIBRDP_STATUS_STATE when the peer is not ACTIVE or output is
 * suppressed; transport or allocation errors from the send path.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_send_desktop_composition_start(librdp_server_peer* peer);

/**
 * @brief Close an open dynamic virtual channel from the server side.
 *
 * @param[in,out] peer Peer that owns the dynamic channel; must not be NULL.
 * @param[in] dynamic_channel_id Open dynamic channel identifier.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * peer or unknown channel; LIBRDP_STATUS_STATE when the peer is not ACTIVE;
 * transport errors for send failures.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_close_dynamic_channel(librdp_server_peer* peer,
                                                                  uint32_t dynamic_channel_id);

/**
 * @brief Return the current peer state.
 *
 * @param[in] peer Peer to query, or NULL.
 *
 * @return Current state, or LIBRDP_SERVER_PEER_FAILED when peer is NULL.
 *
 * @note Thread-safety: read from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_server_peer_state librdp_server_peer_get_state(const librdp_server_peer* peer);

/**
 * @brief Close a peer transport without freeing the peer handle.
 *
 * The call is idempotent. It moves the peer to LIBRDP_SERVER_PEER_CLOSED,
 * emits a state event when appropriate, and leaves metrics/status available
 * until librdp_server_peer_free().
 *
 * @param[in,out] peer Peer to close; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * peer is NULL.
 *
 * @note Thread-safety: call from the serialized peer owner context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_server_peer_close(librdp_server_peer* peer);

/**
 * @brief Close and free a server-side peer.
 *
 * Passing NULL is allowed. The peer socket and buffered negotiation state are
 * released.
 *
 * @param[in,out] peer Peer to free, or NULL.
 *
 * @note Thread-safety: the caller must ensure no other thread is driving the
 * same peer.
 * @since 0.1.0
 */
LIBRDP_API void librdp_server_peer_free(librdp_server_peer* peer);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
