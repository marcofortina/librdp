/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_SERVER_H
#define LIBRDP_SERVER_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

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
#define LIBRDP_SERVER_STATIC_CHANNEL_NAME_CAPACITY 9u /**< Static-channel name storage including NUL. */

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
    LIBRDP_SERVER_PEER_ACTIVE = 11       /**< Client confirmed activation and the peer is ready for runtime PDUs. */
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
