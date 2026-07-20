/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal redirected filesystem contracts.
 * Invariants: redirected file handles are tied to a device id, file id, and
 * root dirfd policy before any host filesystem operation.
 * Ownership: redirected file entries and path strings are session-owned and
 * reset through rdp_session_redirected_file_reset().
 * Threading: filesystem redirection handlers run on the session owner thread.
 * Trust boundary: remote paths, offsets, information classes, and locks are
 * untrusted device-channel input.
 */

#ifndef RDP_CLIENT_SESSION_FILESYSTEM_H
#define RDP_CLIENT_SESSION_FILESYSTEM_H

#include <librdp/session.h>

#include "channels/filesystem_redirection.h"
#include "common/buffer.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

struct rdp_session_redirected_file;

void rdp_session_redirected_file_reset(struct rdp_session_redirected_file* file);
void rdp_session_redirected_files_clear(librdp_session* session);
void rdp_session_drive_roots_clear(librdp_session* session);
uint32_t rdp_session_drive_root_fd(librdp_session* session, uint32_t drive_index, int* fd);
struct rdp_session_redirected_file* rdp_session_redirected_file_find(librdp_session* session,
                                                                     uint32_t device_id,
                                                                     uint32_t file_id);
struct rdp_session_redirected_file* rdp_session_redirected_file_alloc(librdp_session* session,
                                                                      uint32_t device_id,
                                                                      uint32_t* file_id);
uint32_t rdp_session_drive_index_from_device_id(const librdp_session* session, uint32_t device_id);
uint32_t rdp_session_printer_index_from_device_id(const librdp_session* session, uint32_t device_id);
uint32_t rdp_session_smartcard_index_from_device_id(const librdp_session* session, uint32_t device_id);
uint32_t rdp_session_serial_port_index_from_device_id(const librdp_session* session, uint32_t device_id);
uint32_t rdp_session_parallel_port_index_from_device_id(const librdp_session* session, uint32_t device_id);
char* rdp_session_strdup_range(const char* data, size_t length);
uint32_t rdp_session_filesystem_error_from_status(librdp_status status);
uint32_t rdp_session_read_u32_le_unaligned(const uint8_t* data);
librdp_status rdp_session_write_file_information(rdp_buffer* buffer,
                                                 uint32_t information_class,
                                                 const struct stat* st,
                                                 const struct rdp_session_redirected_file* file);
librdp_status rdp_session_write_directory_information(rdp_buffer* buffer,
                                                      uint32_t information_class,
                                                      const struct stat* st,
                                                      const char* name);
librdp_status rdp_session_write_information_response(
    rdp_buffer* response,
    uint32_t device_id,
    uint32_t completion_id,
    uint32_t io_status,
    const rdp_buffer* information);
int rdp_session_seek_fd(int fd, uint64_t offset);
librdp_status rdp_session_utf16le_path_to_utf8(const uint8_t* data, uint32_t data_len, char** out);
uint32_t rdp_session_apply_basic_information(struct rdp_session_redirected_file* file,
                                             const uint8_t* data,
                                             uint32_t data_len);
uint32_t rdp_session_apply_size_information(struct rdp_session_redirected_file* file,
                                            const uint8_t* data,
                                            uint32_t data_len);
uint32_t rdp_session_apply_valid_data_length_information(struct rdp_session_redirected_file* file,
                                                         const uint8_t* data,
                                                         uint32_t data_len);
uint32_t rdp_session_apply_position_information(struct rdp_session_redirected_file* file,
                                                const uint8_t* data,
                                                uint32_t data_len);
uint32_t rdp_session_apply_mode_information(struct rdp_session_redirected_file* file,
                                            const uint8_t* data,
                                            uint32_t data_len);
uint32_t rdp_session_apply_case_sensitive_information(const uint8_t* data, uint32_t data_len);
uint32_t rdp_session_apply_disposition_information(struct rdp_session_redirected_file* file,
                                                   const uint8_t* data,
                                                   uint32_t data_len);
uint32_t rdp_session_apply_disposition_information_ex(struct rdp_session_redirected_file* file,
                                                      const uint8_t* data,
                                                      uint32_t data_len);
uint32_t rdp_session_apply_file_locks(librdp_session* session,
                                      struct rdp_session_redirected_file* file,
                                      const rdp_filesystem_redirection_lock_request* request);
librdp_status rdp_session_handle_filesystem_io_request(librdp_session* session,
                                                       const uint8_t* data,
                                                       size_t data_len);

#endif
