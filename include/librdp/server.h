/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_SERVER_H
#define LIBRDP_SERVER_H

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
