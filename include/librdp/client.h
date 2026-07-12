/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_CLIENT_H
#define LIBRDP_CLIENT_H

#include <stdint.h>

#include <librdp/error.h>
#include <librdp/session.h>
#include <librdp/settings.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup librdp_client Client API
 * @brief Compatibility client facade built on settings and session objects.
 * @{
 */

#define LIBRDP_CLIENT_CONFIG_VERSION 1u /**< Current librdp_client_config version. */

/**
 * @brief Opaque client facade handle.
 *
 * The handle owns one settings object and one session object. It exists as a
 * convenience layer for applications that prefer client/client_config naming;
 * the underlying settings/session APIs remain stable and usable directly.
 *
 * @since 0.1.0
 */
typedef struct librdp_client librdp_client;

/**
 * @brief Versioned client configuration used by librdp_client_new().
 *
 * Initialize with librdp_client_config_init(). Strings are borrowed during the
 * call to librdp_client_new() and copied into the owned settings object when
 * supplied. password is treated as sensitive and is stored through the secure
 * settings password path.
 *
 * @since 0.1.0
 */
typedef struct librdp_client_config
{
    uint32_t version;              /**< Struct version, LIBRDP_CLIENT_CONFIG_VERSION. */
    uint32_t size;                 /**< Size of this struct in bytes. */
    const char* target;            /**< Optional target host copied on client creation. */
    uint16_t port;                 /**< Target TCP port; zero keeps settings default. */
    const char* username;          /**< Optional username copied on client creation. */
    const char* password;          /**< Optional password copied and securely cleared by settings. */
    const char* domain;            /**< Optional domain copied on client creation. */
    uint32_t width;                /**< Desktop width; zero keeps settings default. */
    uint32_t height;               /**< Desktop height; zero keeps settings default. */
    librdp_security_mode security; /**< Requested security mode. */
} librdp_client_config;

/**
 * @brief Initialize a client configuration with safe defaults.
 *
 * Defaults match librdp_settings_new(): automatic security negotiation,
 * default port, and default desktop size. Optional strings are NULL.
 *
 * @param[out] config Caller-owned config object; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * config is NULL.
 *
 * @note Thread-safety: this function writes only caller-owned storage.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_client_config_init(librdp_client_config* config);

/**
 * @brief Create a client facade from a versioned config.
 *
 * The config object is borrowed only for the duration of the call. The returned
 * client owns cloned settings and a session, and must be released with
 * librdp_client_free().
 *
 * @param[in] config Initialized config object; must not be NULL.
 *
 * @return Newly allocated client owned by the caller, or NULL for invalid
 * config, invalid settings values, or allocation failure.
 *
 * @note Thread-safety: create and then drive the client from one serialized
 * context unless the application provides external locking.
 * @warning password is copied into secure settings storage. Do not log config
 * contents or reuse the password buffer longer than necessary.
 * @since 0.1.0
 */
LIBRDP_API librdp_client* librdp_client_new(const librdp_client_config* config);

/**
 * @brief Disconnect and free a client facade.
 *
 * Passing NULL is allowed and has no effect. Owned settings and session state
 * are released; borrowed pointers previously returned by this client become
 * invalid.
 *
 * @param[in,out] client Client to free, or NULL.
 *
 * @note Thread-safety: call from the serialized client-driving context.
 * @since 0.1.0
 */
LIBRDP_API void librdp_client_free(librdp_client* client);

/**
 * @brief Return the settings object owned by a client.
 *
 * The returned pointer is borrowed and remains valid until librdp_client_free().
 * It can be used to call existing librdp_settings_* APIs before connecting.
 *
 * @param[in] client Client to query, or NULL.
 *
 * @return Borrowed settings object, or NULL when client is NULL.
 *
 * @note Thread-safety: mutate settings only before connecting or with external
 * synchronization.
 * @since 0.1.0
 */
LIBRDP_API librdp_settings* librdp_client_settings(librdp_client* client);

/**
 * @brief Return the session object owned by a client.
 *
 * The returned pointer is borrowed and remains valid until librdp_client_free().
 * It allows applications to use existing session APIs with the facade.
 *
 * @param[in] client Client to query, or NULL.
 *
 * @return Borrowed session object, or NULL when client is NULL.
 *
 * @note Thread-safety: use from the same serialized context that drives the
 * client.
 * @since 0.1.0
 */
LIBRDP_API librdp_session* librdp_client_session(librdp_client* client);

/**
 * @brief Connect the client using the owned session.
 *
 * This is a compatibility wrapper around librdp_session_connect().
 *
 * @param[in,out] client Client to connect; must not be NULL.
 *
 * @return Status returned by librdp_session_connect(), or
 * LIBRDP_STATUS_INVALID_ARGUMENT when client is NULL.
 *
 * @note Thread-safety: call from the serialized client-driving context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_client_connect(librdp_client* client);

/**
 * @brief Dispatch one client event-loop iteration.
 *
 * This is a compatibility wrapper around librdp_session_run_once().
 *
 * @param[in,out] client Client to dispatch; must not be NULL.
 * @param[in] timeout_ms Maximum wait time in milliseconds; must be non-negative.
 *
 * @return Status returned by librdp_session_run_once(), or
 * LIBRDP_STATUS_INVALID_ARGUMENT when client is NULL.
 *
 * @note Thread-safety: call from the serialized client-driving context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_client_dispatch(librdp_client* client, int timeout_ms);

/**
 * @brief Disconnect the client using the owned session.
 *
 * This is a compatibility wrapper around librdp_session_disconnect().
 *
 * @param[in,out] client Client to disconnect; must not be NULL.
 *
 * @return Status returned by librdp_session_disconnect(), or
 * LIBRDP_STATUS_INVALID_ARGUMENT when client is NULL.
 *
 * @note Thread-safety: call from the serialized client-driving context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_client_disconnect(librdp_client* client);

/**
 * @brief Return the coarse session state for a client.
 *
 * @param[in] client Client to query, or NULL.
 *
 * @return Current session state, or LIBRDP_SESSION_FAILED when client is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the client.
 * @since 0.1.0
 */
LIBRDP_API librdp_session_state librdp_client_state(const librdp_client* client);

/**
 * @brief Return the detailed lifecycle phase for a client.
 *
 * @param[in] client Client to query, or NULL.
 *
 * @return Current lifecycle phase, or LIBRDP_LIFECYCLE_FAILED when client is
 * NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the client.
 * @since 0.1.0
 */
LIBRDP_API librdp_session_lifecycle librdp_client_lifecycle(const librdp_client* client);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
