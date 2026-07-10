#ifndef RDP_CHANNELS_PRINTER_REDIRECTION_H
#define RDP_CHANNELS_PRINTER_REDIRECTION_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "channels/device_redirection.h"
#include "common/buffer.h"

#define RDP_PRINTER_REDIRECTION_ANNOUNCE_FLAG_ASCII 0x00000001u
#define RDP_PRINTER_REDIRECTION_ANNOUNCE_FLAG_DEFAULT 0x00000002u
#define RDP_PRINTER_REDIRECTION_ANNOUNCE_FLAG_NETWORK 0x00000004u
#define RDP_PRINTER_REDIRECTION_ANNOUNCE_FLAG_TS 0x00000008u
#define RDP_PRINTER_REDIRECTION_ANNOUNCE_FLAG_XPS 0x00000010u

#define RDP_PRINTER_REDIRECTION_CACHE_ADD 0x00000001u
#define RDP_PRINTER_REDIRECTION_CACHE_UPDATE 0x00000002u
#define RDP_PRINTER_REDIRECTION_CACHE_DELETE 0x00000003u
#define RDP_PRINTER_REDIRECTION_CACHE_RENAME 0x00000004u

#define RDP_PRINTER_REDIRECTION_FORMAT_RAW "application/vnd.cups-raw"
#define RDP_PRINTER_REDIRECTION_FORMAT_PDF "application/pdf"
#define RDP_PRINTER_REDIRECTION_FORMAT_POSTSCRIPT "application/postscript"
#define RDP_PRINTER_REDIRECTION_FORMAT_XPS "application/vnd.ms-xpsdocument"
#define RDP_PRINTER_REDIRECTION_FORMAT_PNG "image/png"
#define RDP_PRINTER_REDIRECTION_FORMAT_JPEG "image/jpeg"
#define RDP_PRINTER_REDIRECTION_FORMAT_PCL "application/vnd.hp-PCL"

typedef struct rdp_printer_redirection_announce
{
    uint32_t flags;
    uint32_t code_page;
    const uint8_t* pnp_name;
    uint32_t pnp_name_len;
    const uint8_t* driver_name;
    uint32_t driver_name_len;
    const uint8_t* printer_name;
    uint32_t printer_name_len;
    const uint8_t* cached_fields;
    uint32_t cached_fields_len;
} rdp_printer_redirection_announce;

typedef struct rdp_printer_redirection_cache_event
{
    uint32_t event_id;
    char port_name[8];
    const uint8_t* pnp_name;
    uint32_t pnp_name_len;
    const uint8_t* driver_name;
    uint32_t driver_name_len;
    const uint8_t* printer_name;
    uint32_t printer_name_len;
    const uint8_t* old_printer_name;
    uint32_t old_printer_name_len;
    const uint8_t* new_printer_name;
    uint32_t new_printer_name_len;
    const uint8_t* cached_fields;
    uint32_t cached_fields_len;
} rdp_printer_redirection_cache_event;

typedef struct rdp_printer_redirection_xps_mode
{
    uint32_t printer_id;
    uint32_t flags;
} rdp_printer_redirection_xps_mode;

librdp_status rdp_printer_redirection_write_announce_data(
    rdp_buffer* buffer,
    const rdp_printer_redirection_announce* announce);
librdp_status rdp_printer_redirection_detect_document_format(
    const void* data,
    size_t length,
    const char** format);
librdp_status rdp_printer_redirection_parse_announce_data(
    const void* data,
    size_t length,
    rdp_printer_redirection_announce* announce);
librdp_status rdp_printer_redirection_parse_cache_event(
    const void* data,
    size_t length,
    rdp_printer_redirection_cache_event* event);
librdp_status rdp_printer_redirection_write_cache_add(
    rdp_buffer* buffer,
    const char port_name[8],
    const void* pnp_name,
    uint32_t pnp_name_len,
    const void* driver_name,
    uint32_t driver_name_len,
    const void* printer_name,
    uint32_t printer_name_len,
    const void* cached_fields,
    uint32_t cached_fields_len);
librdp_status rdp_printer_redirection_write_cache_update(
    rdp_buffer* buffer,
    const void* printer_name,
    uint32_t printer_name_len,
    const void* cached_fields,
    uint32_t cached_fields_len);
librdp_status rdp_printer_redirection_write_cache_delete(
    rdp_buffer* buffer,
    const void* printer_name,
    uint32_t printer_name_len);
librdp_status rdp_printer_redirection_write_cache_rename(
    rdp_buffer* buffer,
    const void* old_printer_name,
    uint32_t old_printer_name_len,
    const void* new_printer_name,
    uint32_t new_printer_name_len);
librdp_status rdp_printer_redirection_parse_xps_mode(
    const void* data,
    size_t length,
    rdp_printer_redirection_xps_mode* mode);
librdp_status rdp_printer_redirection_write_xps_mode(
    rdp_buffer* buffer,
    uint32_t printer_id,
    uint32_t flags);
librdp_status rdp_printer_redirection_write_create_response(rdp_buffer* buffer,
                                                            uint32_t device_id,
                                                            uint32_t completion_id,
                                                            uint32_t io_status,
                                                            uint32_t file_id);
librdp_status rdp_printer_redirection_parse_create_response(
    const void* data,
    size_t length,
    rdp_device_redirection_io_completion* response,
    uint32_t* file_id);
librdp_status rdp_printer_redirection_write_close_response(rdp_buffer* buffer,
                                                           uint32_t device_id,
                                                           uint32_t completion_id,
                                                           uint32_t io_status);
librdp_status rdp_printer_redirection_parse_close_response(
    const void* data,
    size_t length,
    rdp_device_redirection_io_completion* response);
librdp_status rdp_printer_redirection_write_read_response(rdp_buffer* buffer,
                                                          uint32_t device_id,
                                                          uint32_t completion_id,
                                                          uint32_t io_status,
                                                          const void* data,
                                                          uint32_t data_len);
librdp_status rdp_printer_redirection_parse_read_response(
    const void* data,
    size_t length,
    rdp_device_redirection_io_completion* response,
    const uint8_t** payload,
    uint32_t* payload_len);
librdp_status rdp_printer_redirection_write_write_response(rdp_buffer* buffer,
                                                           uint32_t device_id,
                                                           uint32_t completion_id,
                                                           uint32_t io_status,
                                                           uint32_t written);
librdp_status rdp_printer_redirection_parse_write_response(
    const void* data,
    size_t length,
    rdp_device_redirection_io_completion* response,
    uint32_t* written);
librdp_status rdp_printer_redirection_write_length_response(rdp_buffer* buffer,
                                                            uint32_t device_id,
                                                            uint32_t completion_id,
                                                            uint32_t io_status,
                                                            uint32_t value);
librdp_status rdp_printer_redirection_parse_length_response(
    const void* data,
    size_t length,
    rdp_device_redirection_io_completion* response,
    uint32_t* value);
librdp_status rdp_printer_redirection_write_device_control_response(rdp_buffer* buffer,
                                                                    uint32_t device_id,
                                                                    uint32_t completion_id,
                                                                    uint32_t io_status);
librdp_status rdp_printer_redirection_parse_device_control_response(
    const void* data,
    size_t length,
    rdp_device_redirection_io_completion* response);

#endif
