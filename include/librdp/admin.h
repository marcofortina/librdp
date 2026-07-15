/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_ADMIN_H
#define LIBRDP_ADMIN_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup librdp_admin Admin API
 * @brief Remote administration inventory helpers for RDS-oriented tools.
 * @{
 */

#define LIBRDP_ADMIN_CONFIG_VERSION 1u  /**< Current librdp_admin_config version. */
#define LIBRDP_ADMIN_SESSION_VERSION 1u /**< Current librdp_admin_session version. */
#define LIBRDP_ADMIN_ACTION_VERSION 1u  /**< Current librdp_admin_action version. */

/**
 * @brief Opaque administration handle.
 *
 * The handle owns copied endpoint configuration, credentials, and the last
 * parsed session inventory. Session string pointers returned through
 * librdp_admin_session_at() remain valid until the next query, XML load,
 * clear, or free operation on the same handle.
 *
 * @since 0.1.0
 */
typedef struct librdp_admin librdp_admin;

/**
 * @brief Administration transport backend.
 *
 * The current public backend is WinRM over HTTP(S). The value is explicit so
 * future management transports can be added without changing the configuration
 * structure layout.
 *
 * @since 0.1.0
 */
typedef enum librdp_admin_transport
{
    LIBRDP_ADMIN_TRANSPORT_WINRM = 1 /**< Use WinRM SOAP over HTTP(S). */
} librdp_admin_transport;

/**
 * @brief Remote administration action type.
 *
 * Actions are executed through the configured management transport. The WinRM
 * backend maps the current action set to bounded server-side process requests
 * and requires a numeric session identifier.
 *
 * @since 0.1.0
 */
typedef enum librdp_admin_action_type
{
    LIBRDP_ADMIN_ACTION_LOGOFF = 1,    /**< Log off the selected remote session. */
    LIBRDP_ADMIN_ACTION_DISCONNECT = 2, /**< Disconnect the selected remote session. */
    LIBRDP_ADMIN_ACTION_MESSAGE = 3    /**< Send a text message to the selected remote session. */
} librdp_admin_action_type;

/**
 * @brief Versioned administration endpoint configuration.
 *
 * Initialize with librdp_admin_config_init(). Strings are borrowed during
 * librdp_admin_new() and copied into the handle. password is copied into
 * sensitive storage and zeroized when replaced or freed. endpoint_url is
 * required for librdp_admin_query_sessions(), but is not required when callers
 * load XML directly with librdp_admin_load_sessions_xml().
 *
 * @since 0.1.0
 */
typedef struct librdp_admin_config
{
    uint32_t version; /**< Struct version, LIBRDP_ADMIN_CONFIG_VERSION. */
    uint32_t size;    /**< Size of this struct in bytes. */
    librdp_admin_transport transport; /**< Management transport backend. */
    const char* endpoint_url; /**< Optional WinRM endpoint URL copied on creation. */
    const char* username;     /**< Optional endpoint user name copied on creation. */
    const char* password;     /**< Optional endpoint password copied on creation and zeroized on clear. */
    const char* domain;       /**< Optional authentication domain copied on creation. */
    const char* resource_uri; /**< Optional WinRM resource URI copied on creation; NULL uses the default. */
    uint32_t timeout_ms;      /**< Query timeout in milliseconds, or zero for the default. */
    int allow_insecure_tls;   /**< Non-zero disables TLS verification for explicit lab use only. */
} librdp_admin_config;

/**
 * @brief Versioned borrowed view of one remote session inventory entry.
 *
 * Initialize with librdp_admin_session_init() before querying a session. String
 * pointers are borrowed from the admin handle and are invalidated by the next
 * admin mutation. Fields may be NULL or zero when the management source did
 * not provide them.
 *
 * @since 0.1.0
 */
typedef struct librdp_admin_session
{
    uint32_t version; /**< Struct version, LIBRDP_ADMIN_SESSION_VERSION. */
    uint32_t size;    /**< Size of this struct in bytes. */
    uint32_t session_id;     /**< RDS session identifier, or zero when not reported. */
    uint64_t logon_id;       /**< Windows logon identifier, or zero when not reported. */
    const char* username;    /**< Borrowed user name, or NULL. */
    const char* domain;      /**< Borrowed user domain, or NULL. */
    const char* state;       /**< Borrowed session state, or NULL. */
    const char* client_name; /**< Borrowed client name, or NULL. */
    const char* station_name; /**< Borrowed station or window station name, or NULL. */
    const char* protocol_name; /**< Borrowed protocol name, or NULL. */
} librdp_admin_session;

/**
 * @brief Versioned remote administration action request.
 *
 * Initialize with librdp_admin_action_init(). session_id is required for every
 * action. message_text is required only for LIBRDP_ADMIN_ACTION_MESSAGE and is
 * borrowed during librdp_admin_execute_action(). message_title is optional.
 * The backend rejects shell metacharacters in message fields before building a
 * WinRM command request.
 *
 * @since 0.1.0
 */
typedef struct librdp_admin_action
{
    uint32_t version; /**< Struct version, LIBRDP_ADMIN_ACTION_VERSION. */
    uint32_t size;    /**< Size of this struct in bytes. */
    librdp_admin_action_type type; /**< Action to execute. */
    uint32_t session_id;           /**< Remote session identifier; must be non-zero. */
    const char* message_title;     /**< Optional message title for MESSAGE; borrowed and may be NULL. */
    const char* message_text;      /**< Required message body for MESSAGE; borrowed and must not be NULL. */
    uint32_t timeout_ms;           /**< Action timeout in milliseconds, or zero to use the admin default. */
} librdp_admin_action;

/**
 * @brief Initialize an admin configuration with safe defaults.
 *
 * The default transport is WinRM, the timeout is suitable for interactive
 * tools, and optional strings are NULL.
 *
 * @param[out] config Caller-owned configuration object; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * config is NULL.
 *
 * @note Thread-safety: this function writes only caller-owned storage.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_admin_config_init(librdp_admin_config* config);

/**
 * @brief Initialize an admin session view.
 *
 * @param[out] session Caller-owned session view; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * session is NULL.
 *
 * @note Thread-safety: this function writes only caller-owned storage.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_admin_session_init(librdp_admin_session* session);

/**
 * @brief Initialize an admin action request.
 *
 * @param[out] action Caller-owned action request; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * action is NULL.
 *
 * @note Thread-safety: this function writes only caller-owned storage.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_admin_action_init(librdp_admin_action* action);

/**
 * @brief Create an admin handle from a versioned configuration.
 *
 * The config object is borrowed only during the call. All strings are copied.
 * The returned handle must be released with librdp_admin_free().
 *
 * @param[in] config Initialized configuration object; must not be NULL.
 *
 * @return Newly allocated admin handle owned by the caller, or NULL for
 * invalid config metadata, invalid field values, or allocation failure.
 *
 * @note Thread-safety: drive each admin handle from one serialized context
 * unless the application provides external locking.
 * @warning Endpoint credentials are sensitive. Do not log the configuration or
 * pass sensitive data to unsafe trace sinks.
 * @since 0.1.0
 */
LIBRDP_API librdp_admin* librdp_admin_new(const librdp_admin_config* config);

/**
 * @brief Free an admin handle.
 *
 * Passing NULL is allowed. Session views and strings borrowed from this handle
 * become invalid.
 *
 * @param[in,out] admin Admin handle to free, or NULL.
 *
 * @note Thread-safety: call from the serialized admin-driving context.
 * @since 0.1.0
 */
LIBRDP_API void librdp_admin_free(librdp_admin* admin);

/**
 * @brief Clear parsed session inventory entries.
 *
 * Endpoint configuration is retained. Borrowed session strings returned by
 * earlier queries become invalid.
 *
 * @param[in,out] admin Admin handle to clear; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * admin is NULL.
 *
 * @note Thread-safety: call from the serialized admin-driving context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_admin_clear(librdp_admin* admin);

/**
 * @brief Query the configured endpoint for remote session inventory.
 *
 * Existing sessions are replaced only after a successful query and parse. When
 * the HTTP or XML backend is not compiled, the function returns
 * LIBRDP_STATUS_UNSUPPORTED.
 *
 * @param[in,out] admin Admin handle to update; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * admin or missing endpoint_url; LIBRDP_STATUS_UNSUPPORTED when required
 * backends are not compiled; LIBRDP_STATUS_IO_ERROR for transport failures;
 * LIBRDP_STATUS_PROTOCOL_ERROR for malformed management XML;
 * LIBRDP_STATUS_TIMEOUT for request timeout; LIBRDP_STATUS_LIMIT_EXCEEDED for
 * response or entry limits; LIBRDP_STATUS_NO_MEMORY for allocation failure.
 *
 * @note Thread-safety: this function performs synchronous network I/O on the
 * caller's thread.
 * @warning Query credentials and returned inventory can be sensitive. Trace
 * output must not include passwords or authentication tokens.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_admin_query_sessions(librdp_admin* admin);

/**
 * @brief Execute a remote administration action.
 *
 * The action is sent through the configured admin transport. The WinRM backend
 * performs synchronous HTTP(S) I/O on the caller thread and returns only after
 * the endpoint responds or the timeout expires.
 *
 * @param[in,out] admin Admin handle configured with an endpoint; must not be NULL.
 * @param[in] action Initialized action request; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * arguments or invalid action metadata; LIBRDP_STATUS_UNSUPPORTED when the
 * required backend is not compiled; LIBRDP_STATUS_IO_ERROR for transport or
 * non-success action responses; LIBRDP_STATUS_TIMEOUT for request timeout;
 * LIBRDP_STATUS_NO_MEMORY for allocation failure.
 *
 * @note Thread-safety: call from the serialized admin-driving context.
 * @warning Logoff and disconnect are disruptive operations. Message contents
 * may be visible to the remote user and must not contain secrets.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_admin_execute_action(librdp_admin* admin,
                                                     const librdp_admin_action* action);

/**
 * @brief Parse session inventory XML from caller-provided memory.
 *
 * The input buffer is read during the call and is not retained. Existing
 * sessions are replaced only after a successful parse. When the XML backend is
 * not compiled, the function returns LIBRDP_STATUS_UNSUPPORTED.
 *
 * @param[in,out] admin Admin handle to update; must not be NULL.
 * @param[in] xml XML bytes to parse. NULL is allowed only when xml_len is 0,
 * which is rejected as malformed input.
 * @param[in] xml_len Length of xml in bytes.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * admin or invalid buffer; LIBRDP_STATUS_UNSUPPORTED when XML parsing support
 * is not compiled; LIBRDP_STATUS_PROTOCOL_ERROR for malformed XML;
 * LIBRDP_STATUS_LIMIT_EXCEEDED for response or entry limits;
 * LIBRDP_STATUS_NO_MEMORY for allocation failure.
 *
 * @note Thread-safety: call from the serialized admin-driving context.
 * @warning Management XML is untrusted input. Applications should treat
 * returned inventory as operational data and apply their own disclosure
 * policy.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_admin_load_sessions_xml(librdp_admin* admin,
                                                       const void* xml,
                                                       size_t xml_len);

/**
 * @brief Return the number of parsed admin session entries.
 *
 * @param[in] admin Admin handle to inspect; may be NULL.
 *
 * @return Parsed session count, or zero when admin is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while the admin handle
 * is not being mutated or freed by another thread.
 * @since 0.1.0
 */
LIBRDP_API size_t librdp_admin_session_count(const librdp_admin* admin);

/**
 * @brief Copy a borrowed view of one parsed admin session entry.
 *
 * session must have been initialized with librdp_admin_session_init(). Only
 * fields that fit within session->size are written.
 *
 * @param[in] admin Admin handle to inspect; must not be NULL.
 * @param[in] index Zero-based session index, less than
 * librdp_admin_session_count().
 * @param[in,out] session Initialized destination view; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * arguments, invalid session metadata, or out-of-range index.
 *
 * @note Thread-safety: concurrent reads are safe only while the admin handle
 * is not being mutated or freed by another thread.
 * @warning Returned string pointers are borrowed and invalidated by later
 * admin mutations or free.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_admin_session_at(const librdp_admin* admin,
                                                size_t index,
                                                librdp_admin_session* session);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
