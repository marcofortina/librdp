#ifndef RDP_CHANNELS_FILESYSTEM_REDIRECTION_H
#define RDP_CHANNELS_FILESYSTEM_REDIRECTION_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "channels/device_redirection.h"
#include "common/buffer.h"

#define RDP_FILESYSTEM_REDIRECTION_MINOR_QUERY_DIRECTORY 0x00000001u
#define RDP_FILESYSTEM_REDIRECTION_MINOR_NOTIFY_CHANGE_DIRECTORY 0x00000002u

#define RDP_FILESYSTEM_REDIRECTION_LOWIO_SHAREDLOCK 0x00000002u
#define RDP_FILESYSTEM_REDIRECTION_LOWIO_EXCLUSIVELOCK 0x00000003u
#define RDP_FILESYSTEM_REDIRECTION_LOWIO_UNLOCK 0x00000004u
#define RDP_FILESYSTEM_REDIRECTION_LOWIO_UNLOCK_MULTIPLE 0x00000005u

#define RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_SUPERSEDED 0x00u
#define RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_OPENED 0x01u
#define RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_CREATED 0x02u
#define RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_OVERWRITTEN 0x03u
#define RDP_FILESYSTEM_REDIRECTION_MAX_LOCKS 64u

#define RDP_FILESYSTEM_REDIRECTION_FSCTL_GET_COMPRESSION 0x0009003cu
#define RDP_FILESYSTEM_REDIRECTION_FSCTL_SET_COMPRESSION 0x0009c040u
#define RDP_FILESYSTEM_REDIRECTION_FSCTL_SET_SPARSE 0x000900c4u
#define RDP_FILESYSTEM_REDIRECTION_FSCTL_SET_ZERO_DATA 0x000980c8u
#define RDP_FILESYSTEM_REDIRECTION_FSCTL_QUERY_ALLOCATED_RANGES 0x000940cfu

typedef struct rdp_filesystem_redirection_create_request
{
    rdp_device_redirection_io_request io;
    uint32_t desired_access;
    uint64_t allocation_size;
    uint32_t file_attributes;
    uint32_t shared_access;
    uint32_t create_disposition;
    uint32_t create_options;
    uint32_t path_len;
    const uint8_t* path;
} rdp_filesystem_redirection_create_request;

typedef struct rdp_filesystem_redirection_read_request
{
    rdp_device_redirection_io_request io;
    uint32_t length;
    uint64_t offset;
} rdp_filesystem_redirection_read_request;

typedef struct rdp_filesystem_redirection_write_request
{
    rdp_device_redirection_io_request io;
    uint32_t length;
    uint64_t offset;
    const uint8_t* data;
} rdp_filesystem_redirection_write_request;

typedef struct rdp_filesystem_redirection_control_request
{
    rdp_device_redirection_io_request io;
    uint32_t output_buffer_length;
    uint32_t input_buffer_length;
    uint32_t io_control_code;
    const uint8_t* input_buffer;
} rdp_filesystem_redirection_control_request;

typedef struct rdp_filesystem_redirection_information_request
{
    rdp_device_redirection_io_request io;
    uint32_t information_class;
    uint32_t length;
    const uint8_t* buffer;
} rdp_filesystem_redirection_information_request;

typedef struct rdp_filesystem_redirection_query_directory_request
{
    rdp_device_redirection_io_request io;
    uint32_t information_class;
    uint8_t initial_query;
    uint32_t path_len;
    const uint8_t* path;
} rdp_filesystem_redirection_query_directory_request;

typedef struct rdp_filesystem_redirection_notify_change_request
{
    rdp_device_redirection_io_request io;
    uint8_t watch_tree;
    uint32_t completion_filter;
} rdp_filesystem_redirection_notify_change_request;

typedef struct rdp_filesystem_redirection_lock_info
{
    uint64_t length;
    uint64_t offset;
} rdp_filesystem_redirection_lock_info;

typedef struct rdp_filesystem_redirection_lock_request
{
    rdp_device_redirection_io_request io;
    uint32_t operation;
    uint32_t flags;
    uint32_t lock_count;
    rdp_filesystem_redirection_lock_info locks[RDP_FILESYSTEM_REDIRECTION_MAX_LOCKS];
} rdp_filesystem_redirection_lock_request;

typedef struct rdp_filesystem_redirection_security_request
{
    rdp_device_redirection_io_request io;
    uint32_t security_information;
    uint32_t length;
    const uint8_t* buffer;
} rdp_filesystem_redirection_security_request;

typedef struct rdp_filesystem_redirection_create_response
{
    rdp_device_redirection_io_completion io;
    uint32_t file_id;
    uint8_t information;
} rdp_filesystem_redirection_create_response;

typedef struct rdp_filesystem_redirection_length_response
{
    rdp_device_redirection_io_completion io;
    uint32_t length;
    const uint8_t* buffer;
    size_t buffer_len;
} rdp_filesystem_redirection_length_response;

librdp_status rdp_filesystem_redirection_parse_create_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_create_request* request);
librdp_status rdp_filesystem_redirection_parse_close_request(
    const void* data,
    size_t length,
    rdp_device_redirection_io_request* request);
librdp_status rdp_filesystem_redirection_parse_read_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_read_request* request);
librdp_status rdp_filesystem_redirection_parse_write_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_write_request* request);
librdp_status rdp_filesystem_redirection_parse_control_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_control_request* request);
librdp_status rdp_filesystem_redirection_parse_query_volume_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_information_request* request);
librdp_status rdp_filesystem_redirection_parse_set_volume_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_information_request* request);
librdp_status rdp_filesystem_redirection_parse_query_information_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_information_request* request);
librdp_status rdp_filesystem_redirection_parse_set_information_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_information_request* request);
librdp_status rdp_filesystem_redirection_parse_query_directory_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_query_directory_request* request);
librdp_status rdp_filesystem_redirection_parse_notify_change_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_notify_change_request* request);
librdp_status rdp_filesystem_redirection_parse_lock_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_lock_request* request);
librdp_status rdp_filesystem_redirection_parse_query_security_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_security_request* request);
librdp_status rdp_filesystem_redirection_parse_set_security_request(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_security_request* request);
librdp_status rdp_filesystem_redirection_write_create_request(
    rdp_buffer* buffer,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id,
    uint32_t desired_access,
    uint64_t allocation_size,
    uint32_t file_attributes,
    uint32_t shared_access,
    uint32_t create_disposition,
    uint32_t create_options,
    const void* path,
    uint32_t path_len);
librdp_status rdp_filesystem_redirection_write_close_request(
    rdp_buffer* buffer,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id);
librdp_status rdp_filesystem_redirection_write_read_request(
    rdp_buffer* buffer,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id,
    uint32_t length,
    uint64_t offset);
librdp_status rdp_filesystem_redirection_write_write_request(
    rdp_buffer* buffer,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id,
    uint64_t offset,
    const void* data,
    uint32_t data_len);
librdp_status rdp_filesystem_redirection_write_control_request(
    rdp_buffer* buffer,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id,
    uint32_t output_buffer_length,
    uint32_t io_control_code,
    const void* input,
    uint32_t input_len);
librdp_status rdp_filesystem_redirection_write_information_request(
    rdp_buffer* buffer,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id,
    uint32_t major_function,
    uint32_t information_class,
    const void* data,
    uint32_t data_len);
librdp_status rdp_filesystem_redirection_write_query_directory_request(
    rdp_buffer* buffer,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id,
    uint32_t information_class,
    uint8_t initial_query,
    const void* path,
    uint32_t path_len);
librdp_status rdp_filesystem_redirection_write_notify_change_request(
    rdp_buffer* buffer,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id,
    uint8_t watch_tree,
    uint32_t completion_filter);
librdp_status rdp_filesystem_redirection_write_lock_request(
    rdp_buffer* buffer,
    uint32_t device_id,
    uint32_t file_id,
    uint32_t completion_id,
    uint32_t operation,
    uint32_t flags,
    const rdp_filesystem_redirection_lock_info* locks,
    uint32_t lock_count);
librdp_status rdp_filesystem_redirection_write_security_request(rdp_buffer* buffer,
                                                                uint32_t device_id,
                                                                uint32_t file_id,
                                                                uint32_t completion_id,
                                                                uint32_t major_function,
                                                                uint32_t security_information,
                                                                const void* data,
                                                                uint32_t data_len);

int rdp_filesystem_redirection_fsctl_supported(uint32_t code);
librdp_status rdp_filesystem_redirection_write_create_response(rdp_buffer* buffer,
                                                               uint32_t device_id,
                                                               uint32_t completion_id,
                                                               uint32_t io_status,
                                                               uint32_t file_id,
                                                               uint8_t information);
librdp_status rdp_filesystem_redirection_parse_create_response(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_create_response* response);
librdp_status rdp_filesystem_redirection_write_close_response(rdp_buffer* buffer,
                                                              uint32_t device_id,
                                                              uint32_t completion_id,
                                                              uint32_t io_status);
librdp_status rdp_filesystem_redirection_parse_close_response(
    const void* data,
    size_t length,
    rdp_device_redirection_io_completion* response);
librdp_status rdp_filesystem_redirection_write_read_response(rdp_buffer* buffer,
                                                             uint32_t device_id,
                                                             uint32_t completion_id,
                                                             uint32_t io_status,
                                                             const void* data,
                                                             uint32_t data_len);
librdp_status rdp_filesystem_redirection_write_write_response(rdp_buffer* buffer,
                                                              uint32_t device_id,
                                                              uint32_t completion_id,
                                                              uint32_t io_status,
                                                              uint32_t written);
librdp_status rdp_filesystem_redirection_write_buffer_response(rdp_buffer* buffer,
                                                               uint32_t device_id,
                                                               uint32_t completion_id,
                                                               uint32_t io_status,
                                                               const void* data,
                                                               uint32_t data_len);
librdp_status rdp_filesystem_redirection_write_length_response(rdp_buffer* buffer,
                                                               uint32_t device_id,
                                                               uint32_t completion_id,
                                                               uint32_t io_status,
                                                               uint32_t length);
librdp_status rdp_filesystem_redirection_parse_length_response(
    const void* data,
    size_t length,
    rdp_filesystem_redirection_length_response* response);
librdp_status rdp_filesystem_redirection_write_lock_response(rdp_buffer* buffer,
                                                             uint32_t device_id,
                                                             uint32_t completion_id,
                                                             uint32_t io_status);
librdp_status rdp_filesystem_redirection_parse_lock_response(
    const void* data,
    size_t length,
    rdp_device_redirection_io_completion* response);

#endif
