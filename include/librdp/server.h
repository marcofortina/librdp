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
#define LIBRDP_SERVER_CHANNEL_EVENT_VERSION 1u /**< Current librdp_server_channel_event version. */
#define LIBRDP_SERVER_EVENT_VERSION 1u /**< Current librdp_server_event version. */
#define LIBRDP_SERVER_STATUS_VERSION 1u /**< Current librdp_server_status version. */
#define LIBRDP_SERVER_METRICS_VERSION 1u /**< Current librdp_server_metrics version. */
#define LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY 9u /**< Static-channel name storage including NUL. */
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
    LIBRDP_SERVER_PEER_TLS_HANDSHAKING = 13 /**< TLS transport handshake is in progress after X.224. */
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
} librdp_server_channel_event;

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
    uint32_t width;        /**< Default desktop width reserved for future activation; zero uses default. */
    uint32_t height;       /**< Default desktop height reserved for future activation; zero uses default. */
    const char* server_name; /**< Optional diagnostic server name copied on creation. */
    librdp_security_mode security_mode; /**< Server security policy; STANDARD is the default. */
    const char* tls_certificate_path; /**< PEM certificate path for TLS/NLA modes; copied on creation. */
    const char* tls_private_key_path; /**< PEM private-key path for TLS/NLA modes; copied on creation. */
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
 * server runtime never advertises a feature unless a real server-side runtime
 * path is present; unsupported feature requests are visible through
 * librdp_server_get_feature_status() with backend availability kept false, and
 * inherited by future peers. Existing peers keep the request set copied when
 * they were accepted.
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
 * @brief Query local server readiness for one optional feature.
 *
 * The function reports the requested state configured on the server object and
 * whether a server-side runtime and backend are available for the feature.
 * Client-only or parser-only features are never reported as active by this
 * server API.
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
 * Passing NULL disables the callback and leaves user_data stored for no future
 * use. The callback runs synchronously from librdp_server_peer_run_once().
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
 * Passing NULL disables the callback and leaves user_data stored for no future
 * use. The callback runs synchronously from librdp_server_peer_run_once().
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
 * @brief Query runtime readiness for one optional feature on a peer.
 *
 * The returned status starts from the feature requests copied from the server
 * object at accept time, then adds peer-observed negotiation and active state
 * for server runtimes that exist. Unsupported features keep backend_ready,
 * negotiated, and active clear even if the client advertised a related static
 * channel.
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
