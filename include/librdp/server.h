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
 * @brief Minimal server-side listener and peer lifecycle primitives.
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
    uint32_t max_peers;    /**< Maximum accepted peers tracked by the listener; zero uses a safe default. */
    uint32_t width;        /**< Default desktop width reserved for future activation; zero uses default. */
    uint32_t height;       /**< Default desktop height reserved for future activation; zero uses default. */
    const char* server_name; /**< Optional diagnostic server name copied on creation. */
} librdp_server_config;

/**
 * @brief Initialize a server configuration with safe defaults.
 *
 * Defaults bind to loopback on an ephemeral port, use a small listen backlog,
 * and reserve a 1024x768 desktop size for future server activation work.
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

/** @} */

#ifdef __cplusplus
}
#endif

#endif
