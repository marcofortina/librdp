/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_CLIPBOARD_H
#define LIBRDP_CLIPBOARD_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup librdp_clipboard Clipboard API
 * @brief Clipboard format, data, file-list, and file-content functions.
 * @{
 */

/**
 * @brief Opaque client session handle used by clipboard APIs.
 *
 * The handle is owned by the caller after librdp_session_new() and remains
 * valid until librdp_session_free().
 *
 * @since 0.1.0
 */
typedef struct librdp_session librdp_session;

#define LIBRDP_CLIPBOARD_FORMAT_TEXT 1u        /**< ANSI text clipboard format identifier. */
#define LIBRDP_CLIPBOARD_FORMAT_BITMAP 2u      /**< Bitmap clipboard format identifier. */
#define LIBRDP_CLIPBOARD_FORMAT_DIB 8u         /**< Device-independent bitmap clipboard format identifier. */
#define LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT 13u /**< UTF-16 text clipboard format identifier. */
#define LIBRDP_CLIPBOARD_FORMAT_HDROP 15u      /**< File-list clipboard format identifier. */
#define LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW 0xc001u /**< Registered file-descriptor list identifier. */
#define LIBRDP_CLIPBOARD_FORMAT_FILECONTENTS 0xc002u /**< Registered file-content stream identifier. */
#define LIBRDP_CLIPBOARD_FORMAT_HTML 0xc100u   /**< Local registered HTML clipboard format identifier. */
#define LIBRDP_CLIPBOARD_FORMAT_PNG 0xc101u    /**< Local registered PNG clipboard format identifier. */
#define LIBRDP_CLIPBOARD_FORMAT_NAME_HTML "HTML Format" /**< Registered HTML clipboard format name. */
#define LIBRDP_CLIPBOARD_FORMAT_NAME_PNG "PNG"          /**< Registered PNG clipboard format name. */
#define LIBRDP_CLIPBOARD_FORMAT_NAME_FILEGROUPDESCRIPTORW "FileGroupDescriptorW" /**< Registered file-list format name. */
#define LIBRDP_CLIPBOARD_CAP_USE_LONG_FORMAT_NAMES 0x00000002u /**< Negotiate long clipboard format names. */
#define LIBRDP_CLIPBOARD_CAP_STREAM_FILECLIP_ENABLED 0x00000004u /**< Negotiate streamed file clipboard data. */
#define LIBRDP_CLIPBOARD_CAP_FILECLIP_NO_FILE_PATHS 0x00000008u /**< Omit local filesystem paths from file metadata. */
#define LIBRDP_CLIPBOARD_CAP_CAN_LOCK_CLIPDATA 0x00000010u /**< Negotiate clipboard generation locking. */
#define LIBRDP_CLIPBOARD_CAP_HUGE_FILE_SUPPORT 0x00000020u /**< Negotiate 64-bit file offsets. */
#define LIBRDP_CLIPBOARD_FILECONTENTS_SIZE 0x00000001u /**< Request file size metadata. */
#define LIBRDP_CLIPBOARD_FILECONTENTS_RANGE 0x00000002u /**< Request one file byte range. */
#define LIBRDP_CLIPBOARD_FILE_METADATA_VERSION 1u /**< Current librdp_clipboard_file_metadata version. */
#define LIBRDP_CLIPBOARD_FILE_ATTRIBUTE_READONLY 0x00000001u /**< Read-only file attribute. */
#define LIBRDP_CLIPBOARD_FILE_ATTRIBUTE_HIDDEN 0x00000002u /**< Hidden file attribute. */
#define LIBRDP_CLIPBOARD_FILE_ATTRIBUTE_DIRECTORY 0x00000010u /**< Directory file attribute. */
#define LIBRDP_CLIPBOARD_FILE_ATTRIBUTE_ARCHIVE 0x00000020u /**< Archive file attribute. */
#define LIBRDP_CLIPBOARD_FILE_ATTRIBUTE_NORMAL 0x00000080u /**< Normal file attribute. */

/**
 * @brief Clipboard format descriptor delivered by format-list events.
 *
 * The name pointer is borrowed from the event payload and is valid only until
 * the event callback returns. Applications must copy it if they need it later.
 *
 * @since 0.1.0
 */
typedef struct librdp_clipboard_format
{
    uint32_t format_id;     /**< Clipboard format identifier. */
    const uint8_t* name;    /**< Optional UTF-16LE format name; may be NULL when name_len is 0. */
    size_t name_len;        /**< Length in bytes of name. */
} librdp_clipboard_format;

/**
 * @brief Local file entry advertised through clipboard file transfer.
 *
 * Both strings are borrowed during the API call and copied into session-owned
 * storage by librdp_session_clipboard_set_files().
 *
 * @since 0.1.0
 */
typedef struct librdp_clipboard_file
{
    const char* path; /**< Host filesystem path; must not be NULL when submitted. */
    const char* name; /**< Advertised file name; must not be NULL when submitted. */
} librdp_clipboard_file;

/**
 * @brief One normalized file-list entry used at platform clipboard boundaries.
 *
 * name is UTF-8. Encoders borrow it only for the duration of the call. Decoders
 * point it at the caller-provided name buffer, which remains caller-owned.
 * Names are individual file names and must not contain path separators.
 *
 * @since 0.1.0
 */
typedef struct librdp_clipboard_file_metadata
{
    uint32_t version; /**< Must be LIBRDP_CLIPBOARD_FILE_METADATA_VERSION. */
    uint32_t size; /**< Size of this structure as seen by the caller. */
    const char* name; /**< Borrowed UTF-8 file name, or NULL after a size query. */
    uint64_t file_size; /**< File size in bytes. */
    uint32_t attributes; /**< LIBRDP_CLIPBOARD_FILE_ATTRIBUTE_* bitmask. */
} librdp_clipboard_file_metadata;

/**
 * @brief Initialize normalized clipboard file metadata.
 *
 * @param[out] metadata Caller-owned metadata object; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * metadata is NULL.
 *
 * @note Thread-safety: this function writes only caller-owned storage.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_clipboard_file_metadata_init(
    librdp_clipboard_file_metadata* metadata);

/**
 * @brief Encode normalized file metadata as a clipboard file-group payload.
 *
 * Every entry must be initialized, contain a non-empty UTF-8 name without path
 * separators, and fit the protocol filename field. The function validates all
 * entries before changing output. Pass output as NULL with output_capacity 0
 * to query the required byte count.
 *
 * @param[in] files Initialized metadata array; must not be NULL.
 * @param[in] count Number of entries; must be non-zero.
 * @param[out] output Caller-owned destination bytes, or NULL for a size query.
 * @param[in] output_capacity Bytes available at output; must be zero when
 * output is NULL.
 * @param[out] output_length Required and, on success, written byte count; must
 * not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success or a valid size query;
 * LIBRDP_STATUS_INVALID_ARGUMENT for malformed arguments, metadata, or names;
 * LIBRDP_STATUS_LIMIT_EXCEEDED when output is too small or the encoded payload
 * cannot be represented; LIBRDP_STATUS_NO_MEMORY on allocation failure;
 * LIBRDP_STATUS_UNSUPPORTED when host character conversion is unavailable.
 *
 * @note Thread-safety: this function uses no shared mutable state.
 * @warning File names can contain sensitive user information. The function
 * does not emit names or payload bytes to trace.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_clipboard_file_group_encode(
    const librdp_clipboard_file_metadata* files,
    uint32_t count,
    void* output,
    size_t output_capacity,
    size_t* output_length);

/**
 * @brief Validate a clipboard file-group payload and return its entry count.
 *
 * @param[in] data File-group payload bytes; must not be NULL.
 * @param[in] data_len Number of bytes available at data.
 * @param[out] count Validated entry count; must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * arguments; LIBRDP_STATUS_PROTOCOL_ERROR for malformed length, count, flags,
 * or unterminated names; LIBRDP_STATUS_LIMIT_EXCEEDED when the entry count
 * cannot be represented safely.
 *
 * @note Thread-safety: this function reads only caller-owned storage.
 * @warning File metadata can contain sensitive user information. The function
 * does not emit names or payload bytes to trace.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_clipboard_file_group_count(
    const void* data,
    size_t data_len,
    uint32_t* count);

/**
 * @brief Decode one entry from a validated clipboard file-group payload.
 *
 * metadata must be initialized before the call. Pass name as NULL with
 * name_capacity 0 to query the UTF-8 byte count, including its trailing NUL.
 * On a successful decode metadata->name points to name. No input pointer is
 * retained.
 *
 * @param[in] data File-group payload bytes; must not be NULL.
 * @param[in] data_len Number of bytes available at data.
 * @param[in] index Zero-based entry index.
 * @param[in,out] metadata Initialized caller-owned result; must not be NULL.
 * @param[out] name Caller-owned UTF-8 destination, or NULL for a size query.
 * @param[in] name_capacity Bytes available at name; must be zero when name is
 * NULL.
 * @param[out] name_length Required byte count including the NUL terminator;
 * must not be NULL.
 *
 * @return LIBRDP_STATUS_OK on success or a valid size query;
 * LIBRDP_STATUS_INVALID_ARGUMENT for invalid arguments or descriptor metadata;
 * LIBRDP_STATUS_PROTOCOL_ERROR for malformed input;
 * LIBRDP_STATUS_LIMIT_EXCEEDED when index is out of range or name is too small;
 * LIBRDP_STATUS_NO_MEMORY on conversion allocation failure;
 * LIBRDP_STATUS_UNSUPPORTED when host character conversion is unavailable.
 *
 * @note Thread-safety: this function uses no shared mutable state.
 * @warning Decoded names can contain sensitive user information. The function
 * does not emit them to trace.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_clipboard_file_group_get(
    const void* data,
    size_t data_len,
    uint32_t index,
    librdp_clipboard_file_metadata* metadata,
    char* name,
    size_t name_capacity,
    size_t* name_length);

/**
 * @brief Advertise one local clipboard data format and payload.
 *
 * Existing local clipboard data or file entries are cleared. The payload is
 * copied into the session during the call; the caller retains ownership of the
 * input buffer.
 *
 * @param[in,out] session Session whose clipboard state is updated; must not be
 * NULL.
 * @param[in] format_id Clipboard format identifier; must be non-zero.
 * @param[in] data Clipboard payload bytes. NULL is allowed only when data_len
 * is 0.
 * @param[in] data_len Payload length in bytes.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid arguments; LIBRDP_STATUS_NO_MEMORY when the payload copy cannot
 * be allocated; LIBRDP_STATUS_STATE or transport errors when the format list
 * cannot be sent in the current session state.
 *
 * @note Thread-safety: sessions are not internally synchronized; call from one
 * serialized session-driving context.
 * @warning Clipboard data can contain sensitive content. The library stores a
 * copy until it is replaced, cleared, or the session is freed. Trace output
 * redacts payload bodies unless unsafe tracing is explicitly enabled.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_clipboard_set_data(librdp_session* session,
                                                uint32_t format_id,
                                                const void* data,
                                                size_t data_len);

/**
 * @brief Advertise one named local clipboard format and payload.
 *
 * Existing local clipboard data or file entries are cleared. The payload is
 * copied into the session during the call; the caller retains ownership of the
 * input buffer. The UTF-8 format name is converted to the wire format and
 * advertised with the supplied local format identifier.
 *
 * @param[in,out] session Session whose clipboard state is updated; must not be
 * NULL.
 * @param[in] format_id Local clipboard format identifier; must be non-zero and
 * stable until replaced or cleared.
 * @param[in] format_name Registered clipboard format name; must not be NULL or
 * empty and remains owned by the caller.
 * @param[in] data Clipboard payload bytes. NULL is allowed only when data_len
 * is 0.
 * @param[in] data_len Payload length in bytes.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid arguments; LIBRDP_STATUS_NO_MEMORY when the payload or converted
 * name cannot be allocated; LIBRDP_STATUS_STATE or transport errors when the
 * format list cannot be sent in the current session state.
 *
 * @note Thread-safety: sessions are not internally synchronized; call from one
 * serialized session-driving context.
 * @warning Named clipboard payloads can contain sensitive application data.
 * The library stores a copy until it is replaced, cleared, or the session is
 * freed. Trace output redacts payload bodies unless unsafe tracing is
 * explicitly enabled.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_clipboard_set_named_data(librdp_session* session,
                                                      uint32_t format_id,
                                                      const char* format_name,
                                                      const void* data,
                                                      size_t data_len);

/**
 * @brief Advertise local files through clipboard file transfer.
 *
 * Existing local clipboard data or file entries are cleared. Each entry must
 * reference an existing regular file. The file path and advertised name are
 * copied into the session; file contents are read later when the server
 * requests ranges.
 *
 * @param[in,out] session Session whose clipboard state is updated; must not be
 * NULL.
 * @param[in] files Array of file descriptors; must not be NULL.
 * @param[in] count Number of file descriptors; must be non-zero and within the
 * implementation limit.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * arguments, invalid count, missing files, non-regular files, or invalid names;
 * LIBRDP_STATUS_NO_MEMORY when metadata cannot be copied; LIBRDP_STATUS_STATE
 * or transport errors when the format list cannot be sent in the current
 * session state.
 *
 * @note Thread-safety: sessions are not internally synchronized; call from one
 * serialized session-driving context.
 * @warning Advertised files may be read by the remote side after this call.
 * The application is responsible for user consent and access policy. Trace
 * output redacts file metadata and payload bodies unless unsafe tracing is
 * explicitly enabled.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_clipboard_set_files(librdp_session* session,
                                                 const librdp_clipboard_file* files,
                                                 uint32_t count);

/**
 * @brief Clear the local clipboard advertisement.
 *
 * Local clipboard data and file metadata stored by the session are released,
 * and an empty format list is sent when clipboard transport is available.
 *
 * @param[in,out] session Session whose clipboard state is cleared; must not be
 * NULL.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT when
 * session is NULL; LIBRDP_STATUS_STATE or transport errors when the empty
 * format list cannot be sent in the current session state.
 *
 * @note Thread-safety: sessions are not internally synchronized; call from one
 * serialized session-driving context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_clipboard_clear(librdp_session* session);

/**
 * @brief Request clipboard data for a remote format.
 *
 * A successful request is asynchronous. The response is delivered through a
 * clipboard data event while the session loop is being driven.
 *
 * @param[in,out] session Connected session; must not be NULL.
 * @param[in] format_id Remote clipboard format identifier; must be non-zero.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid arguments; LIBRDP_STATUS_STATE when the clipboard channel is not
 * ready; allocation or transport errors propagated from the request send path.
 *
 * @note Thread-safety: sessions are not internally synchronized; call from one
 * serialized session-driving context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_clipboard_request_data(librdp_session* session, uint32_t format_id);

/**
 * @brief Request the size of a remote clipboard file.
 *
 * A successful request is asynchronous. The response is delivered through a
 * clipboard file contents event using the same stream identifier.
 *
 * @param[in,out] session Connected session; must not be NULL.
 * @param[in] stream_id Caller-selected stream identifier; must be non-zero.
 * @param[in] file_index Remote file index from the clipboard file list.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid arguments; LIBRDP_STATUS_STATE when the clipboard channel is not
 * ready; allocation or transport errors propagated from the request send path.
 *
 * @note Thread-safety: sessions are not internally synchronized; call from one
 * serialized session-driving context.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_clipboard_request_file_size(librdp_session* session,
                                                         uint32_t stream_id,
                                                         int32_t file_index);

/**
 * @brief Request a byte range from a remote clipboard file.
 *
 * A successful request is asynchronous. The response is delivered through a
 * clipboard file contents event using the same stream identifier.
 *
 * @param[in,out] session Connected session; must not be NULL.
 * @param[in] stream_id Caller-selected stream identifier; must be non-zero.
 * @param[in] file_index Remote file index from the clipboard file list.
 * @param[in] position Starting byte offset in the remote file.
 * @param[in] requested Number of bytes to request; must be non-zero and within
 * the implementation range limit.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL,
 * invalid stream, or invalid range arguments; LIBRDP_STATUS_STATE when the
 * clipboard channel is not ready; allocation or transport errors propagated
 * from the request send path.
 *
 * @note Thread-safety: sessions are not internally synchronized; call from one
 * serialized session-driving context.
 * @warning Requested remote file contents may be sensitive; applications must
 * store or expose returned data according to their own policy. Trace output
 * redacts payload bodies unless unsafe tracing is explicitly enabled.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_session_clipboard_request_file_range(librdp_session* session,
                                                          uint32_t stream_id,
                                                          int32_t file_index,
                                                          uint64_t position,
                                                          uint32_t requested);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
