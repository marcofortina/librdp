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
 * copy until it is replaced, cleared, or the session is freed.
 * @since 0.1.0
 */
librdp_status librdp_session_clipboard_set_data(librdp_session* session,
                                                uint32_t format_id,
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
 * The application is responsible for user consent and access policy.
 * @since 0.1.0
 */
librdp_status librdp_session_clipboard_set_files(librdp_session* session,
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
librdp_status librdp_session_clipboard_clear(librdp_session* session);

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
librdp_status librdp_session_clipboard_request_data(librdp_session* session, uint32_t format_id);

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
librdp_status librdp_session_clipboard_request_file_size(librdp_session* session,
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
 * store or expose returned data according to their own policy.
 * @since 0.1.0
 */
librdp_status librdp_session_clipboard_request_file_range(librdp_session* session,
                                                          uint32_t stream_id,
                                                          int32_t file_index,
                                                          uint64_t position,
                                                          uint32_t requested);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
