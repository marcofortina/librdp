/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_WORKSPACE_H
#define LIBRDP_WORKSPACE_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup librdp_workspace Workspace API
 * @brief Remote workspace feed discovery and published resource inspection.
 * @{
 */

#define LIBRDP_WORKSPACE_CONFIG_VERSION 1u   /**< Current librdp_workspace_config version. */
#define LIBRDP_WORKSPACE_RESOURCE_VERSION 1u /**< Current librdp_workspace_resource version. */

/**
 * @brief Opaque workspace feed handle.
 *
 * A workspace owns the feed configuration copy and the parsed resource list.
 * Resource string pointers returned through librdp_workspace_resource_at() are
 * borrowed from this handle and remain valid until the next fetch, load, clear,
 * or free operation on the same workspace.
 *
 * @since 0.1.0
 */
typedef struct librdp_workspace librdp_workspace;

/**
 * @brief Published workspace resource kind.
 *
 * Values describe the normalized resource class exposed by the workspace feed.
 * Unknown values are retained so callers can present or log feed entries that
 * are not recognized by the current library version.
 *
 * @since 0.1.0
 */
typedef enum librdp_workspace_resource_type
{
    LIBRDP_WORKSPACE_RESOURCE_UNKNOWN = 0,    /**< Resource kind is missing or not recognized. */
    LIBRDP_WORKSPACE_RESOURCE_DESKTOP = 1,    /**< Published full desktop resource. */
    LIBRDP_WORKSPACE_RESOURCE_REMOTE_APP = 2  /**< Published RemoteApp resource. */
} librdp_workspace_resource_type;

/**
 * @brief Versioned workspace feed configuration.
 *
 * Initialize with librdp_workspace_config_init(). Strings are borrowed by
 * librdp_workspace_new() and copied into the workspace. password is copied
 * into sensitive storage and zeroized when replaced or freed. feed_url is
 * required for librdp_workspace_fetch(), but is not required when callers load
 * XML directly with librdp_workspace_load_xml().
 *
 * @since 0.1.0
 */
typedef struct librdp_workspace_config
{
    uint32_t version; /**< Struct version, LIBRDP_WORKSPACE_CONFIG_VERSION. */
    uint32_t size;    /**< Size of this struct in bytes. */
    const char* feed_url; /**< Optional HTTP or HTTPS workspace feed URL copied on creation. */
    const char* username; /**< Optional feed user name copied on creation. */
    const char* password; /**< Optional feed password copied on creation and zeroized on clear. */
    const char* domain;   /**< Optional authentication domain copied on creation. */
    uint32_t timeout_ms;  /**< Feed request timeout in milliseconds, or zero for the default. */
} librdp_workspace_config;

/**
 * @brief Versioned borrowed view of one published workspace resource.
 *
 * Initialize with librdp_workspace_resource_init() before querying a resource.
 * String pointers are borrowed from the workspace and are invalidated by the
 * next workspace mutation. Optional fields are NULL when not present in the
 * feed. rdp_file_contents contains an RDP file payload when the feed embeds
 * one; rdp_file_url contains a URL when the feed points to one instead.
 *
 * @since 0.1.0
 */
typedef struct librdp_workspace_resource
{
    uint32_t version; /**< Struct version, LIBRDP_WORKSPACE_RESOURCE_VERSION. */
    uint32_t size;    /**< Size of this struct in bytes. */
    librdp_workspace_resource_type type; /**< Normalized resource type. */
    const char* id;                 /**< Optional stable feed identifier; borrowed and may be NULL. */
    const char* title;              /**< Display title; borrowed and may be NULL. */
    const char* alias;              /**< Optional resource alias; borrowed and may be NULL. */
    const char* rdp_file_contents;  /**< Optional embedded RDP file contents; borrowed and may be NULL. */
    const char* rdp_file_url;       /**< Optional RDP file URL; borrowed and may be NULL. */
    const char* icon_url;           /**< Optional icon URL; borrowed and may be NULL. */
    const char* terminal_server;    /**< Optional terminal server hint; borrowed and may be NULL. */
    const char* remote_app_program; /**< Optional RemoteApp program identifier; borrowed and may be NULL. */
} librdp_workspace_resource;

/**
 * @brief Initialize a workspace configuration.
 *
 * The default timeout is suitable for interactive feed discovery. Optional
 * strings are initialized to NULL.
 *
 * @param[out] config Caller-owned configuration object; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * config is NULL.
 *
 * @note Thread-safety: this function writes only caller-owned storage.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_workspace_config_init(librdp_workspace_config* config);

/**
 * @brief Initialize a workspace resource view.
 *
 * @param[out] resource Caller-owned resource view; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * resource is NULL.
 *
 * @note Thread-safety: this function writes only caller-owned storage.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_workspace_resource_init(librdp_workspace_resource* resource);

/**
 * @brief Create a workspace handle from a versioned configuration.
 *
 * The config object is borrowed only during the call. All strings are copied.
 * The returned handle must be released with librdp_workspace_free().
 *
 * @param[in] config Initialized configuration object; must not be NULL.
 *
 * @return Newly allocated workspace owned by the caller, or NULL for invalid
 * config metadata, invalid field values, or allocation failure.
 *
 * @note Thread-safety: drive each workspace from one serialized context unless
 * the application provides external locking.
 * @warning Feed credentials are stored only to perform feed requests and are
 * zeroized on cleanup. Do not log the configuration or pass sensitive data to
 * unsafe trace sinks.
 * @since 0.1.0
 */
LIBRDP_API librdp_workspace* librdp_workspace_new(const librdp_workspace_config* config);

/**
 * @brief Free a workspace handle.
 *
 * Passing NULL is allowed. Resource views and strings borrowed from this
 * workspace become invalid.
 *
 * @param[in,out] workspace Workspace handle to free, or NULL.
 *
 * @note Thread-safety: call from the serialized workspace-driving context.
 * @since 0.1.0
 */
LIBRDP_API void librdp_workspace_free(librdp_workspace* workspace);

/**
 * @brief Clear parsed workspace resources.
 *
 * The feed configuration is retained. Borrowed resource strings returned by
 * earlier queries become invalid.
 *
 * @param[in,out] workspace Workspace handle to clear; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * workspace is NULL.
 *
 * @note Thread-safety: call from the serialized workspace-driving context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_workspace_clear(librdp_workspace* workspace);

/**
 * @brief Fetch and parse the configured workspace feed.
 *
 * The configured feed_url is requested through the compiled HTTP backend and
 * parsed into the resource list. Existing resources are replaced only after a
 * successful parse. When the HTTP or XML backend is not compiled, the function
 * returns LIBRDP_STATUS_UNSUPPORTED.
 *
 * @param[in,out] workspace Workspace handle to update; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * workspace or missing feed_url; LIBRDP_STATUS_UNSUPPORTED when the required
 * backend is not compiled; LIBRDP_STATUS_IO_ERROR for feed transport failures;
 * LIBRDP_STATUS_PROTOCOL_ERROR for malformed feed data; LIBRDP_STATUS_TIMEOUT
 * for request timeout; LIBRDP_STATUS_NO_MEMORY for allocation failure.
 *
 * @note Thread-safety: this function performs synchronous network I/O on the
 * caller's thread.
 * @warning The feed request may use credentials configured in the workspace.
 * Trace output must not include passwords or feed authentication tokens.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_workspace_fetch(librdp_workspace* workspace);

/**
 * @brief Parse workspace XML from caller-provided memory.
 *
 * The input buffer is read during the call and is not retained. Existing
 * resources are replaced only after a successful parse. When the XML backend is
 * not compiled, the function returns LIBRDP_STATUS_UNSUPPORTED.
 *
 * @param[in,out] workspace Workspace handle to update; must not be NULL.
 * @param[in] xml XML bytes to parse. NULL is allowed only when xml_len is 0,
 * which is rejected as malformed input.
 * @param[in] xml_len Length of xml in bytes.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * workspace or an invalid buffer; LIBRDP_STATUS_UNSUPPORTED when XML parsing
 * support is not compiled; LIBRDP_STATUS_PROTOCOL_ERROR for malformed XML or
 * unsupported feed structure; LIBRDP_STATUS_LIMIT_EXCEEDED for resource or
 * field limits; LIBRDP_STATUS_NO_MEMORY for allocation failure.
 *
 * @note Thread-safety: call from the serialized workspace-driving context.
 * @warning Workspace feeds can contain launch metadata. Applications should
 * treat returned RDP file contents and URLs as untrusted input until validated
 * by their own launch policy.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_workspace_load_xml(librdp_workspace* workspace,
                                                  const void* xml,
                                                  size_t xml_len);

/**
 * @brief Return the number of parsed workspace resources.
 *
 * @param[in] workspace Workspace handle to inspect; may be NULL.
 *
 * @return Parsed resource count, or zero when workspace is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while the workspace is
 * not being mutated or freed by another thread.
 * @since 0.1.0
 */
LIBRDP_API size_t librdp_workspace_resource_count(const librdp_workspace* workspace);

/**
 * @brief Copy a borrowed view of one parsed workspace resource.
 *
 * resource must have been initialized with librdp_workspace_resource_init().
 * Only fields that fit within resource->size are written.
 *
 * @param[in] workspace Workspace handle to inspect; must not be NULL.
 * @param[in] index Zero-based resource index, less than
 * librdp_workspace_resource_count().
 * @param[in,out] resource Initialized destination view; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * arguments, invalid resource metadata, or out-of-range index.
 *
 * @note Thread-safety: concurrent reads are safe only while the workspace is
 * not being mutated or freed by another thread.
 * @warning Returned string pointers are borrowed and invalidated by later
 * workspace mutations or free.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_workspace_resource_at(const librdp_workspace* workspace,
                                                     size_t index,
                                                     librdp_workspace_resource* resource);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
