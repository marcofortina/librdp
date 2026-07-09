#ifndef RDP_CHANNELS_XPS_PRINT_H
#define RDP_CHANNELS_XPS_PRINT_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_XPS_PRINT_INTERFACE_DEFAULT 0x00000000u
#define RDP_XPS_PRINT_FUNC_RELEASE 0x00000001u
#define RDP_XPS_PRINT_FUNC_QUERY_INTERFACE 0x00000002u

#define RDP_XPS_PRINT_TICKET_GET_SUPPORTED_VERSIONS 0x00000100u
#define RDP_XPS_PRINT_TICKET_BIND_PRINTER 0x00000101u
#define RDP_XPS_PRINT_TICKET_QUERY_DEVICE_NAMESPACE 0x00000102u
#define RDP_XPS_PRINT_TICKET_PRINT_TICKET_TO_DEVMODE 0x00000103u
#define RDP_XPS_PRINT_TICKET_DEVMODE_TO_PRINT_TICKET 0x00000104u
#define RDP_XPS_PRINT_TICKET_PRINT_CAPS 0x00000105u
#define RDP_XPS_PRINT_TICKET_PRINT_CAPS_FROM_TICKET 0x00000106u
#define RDP_XPS_PRINT_TICKET_VALIDATE_PRINT_TICKET 0x00000107u

#define RDP_XPS_PRINT_DRIVER_INIT_PRINTER 0x00000100u
#define RDP_XPS_PRINT_DRIVER_GET_ALL_DEV_CAPS 0x00000101u
#define RDP_XPS_PRINT_DRIVER_CONVERT_DEVMODE 0x00000102u
#define RDP_XPS_PRINT_DRIVER_GET_DEVICE_CAP 0x00000104u
#define RDP_XPS_PRINT_DRIVER_DOC_PROPERTIES 0x00000105u
#define RDP_XPS_PRINT_DRIVER_ASYNC_DOC_PROPERTIES 0x00000106u
#define RDP_XPS_PRINT_DRIVER_ASYNC_PRINTER_PROPERTIES 0x00000107u
#define RDP_XPS_PRINT_DRIVER_CANCEL_ASYNC_DOC_PROPERTIES 0x00000109u
#define RDP_XPS_PRINT_DRIVER_CANCEL_ASYNC_PRINTER_PROPERTIES 0x0000010au
#define RDP_XPS_PRINT_DRIVER_MOVE_DOC_PROPERTIES 0x0000010bu
#define RDP_XPS_PRINT_DRIVER_GET_DEVICE_ADJUSTMENT 0x0000010cu

#define RDP_XPS_PRINT_NULL_ABSENT 0x01u
#define RDP_XPS_PRINT_NULL_PRESENT 0x00u
#define RDP_XPS_PRINT_PROPERTY_INT32 0x00000002u
#define RDP_XPS_PRINT_PROPERTY_INT64 0x00000003u
#define RDP_XPS_PRINT_PROPERTY_INT8 0x00000004u
#define RDP_XPS_PRINT_PROPERTY_BUFFER 0x0000000au

typedef struct rdp_xps_print_header
{
    uint32_t interface_id;
    uint32_t message_id;
    uint8_t has_function_id;
    uint32_t function_id;
    const uint8_t* payload;
    size_t payload_len;
} rdp_xps_print_header;

typedef struct rdp_xps_print_interface_query
{
    rdp_xps_print_header header;
    uint8_t guid[16];
} rdp_xps_print_interface_query;

typedef struct rdp_xps_print_interface_query_response
{
    rdp_xps_print_header header;
    uint8_t has_new_interface_id;
    uint32_t new_interface_id;
} rdp_xps_print_interface_query_response;

typedef struct rdp_xps_print_xml_document
{
    uint32_t size;
    const uint8_t* data;
} rdp_xps_print_xml_document;

typedef struct rdp_xps_print_device_capability
{
    uint32_t return_value;
    uint32_t error_code;
    uint16_t data_len;
    const uint8_t* data;
} rdp_xps_print_device_capability;

typedef struct rdp_xps_print_printer_property
{
    uint32_t property_type;
    uint32_t name_len;
    const uint8_t* name;
    uint32_t value_len;
    const uint8_t* value;
} rdp_xps_print_printer_property;

typedef struct rdp_xps_print_u32_request
{
    rdp_xps_print_header header;
    uint32_t value;
} rdp_xps_print_u32_request;

typedef struct rdp_xps_print_versions_response
{
    rdp_xps_print_header header;
    uint32_t version_count;
    const uint8_t* versions;
    uint32_t result;
} rdp_xps_print_versions_response;

typedef struct rdp_xps_print_blob_result
{
    rdp_xps_print_header header;
    uint32_t data_len;
    const uint8_t* data;
    uint32_t result;
} rdp_xps_print_blob_result;

typedef struct rdp_xps_print_optional_blob_result
{
    rdp_xps_print_header header;
    uint8_t null_flag;
    const uint8_t* data;
    size_t data_len;
    uint32_t result;
} rdp_xps_print_optional_blob_result;

typedef struct rdp_xps_print_result
{
    rdp_xps_print_header header;
    uint32_t result;
} rdp_xps_print_result;

librdp_status rdp_xps_print_parse_header(const void* data,
                                         size_t length,
                                         uint8_t has_function_id,
                                         rdp_xps_print_header* header);
librdp_status rdp_xps_print_write_header(rdp_buffer* buffer,
                                         uint32_t interface_id,
                                         uint32_t message_id,
                                         uint8_t has_function_id,
                                         uint32_t function_id);
librdp_status rdp_xps_print_parse_interface_query(const void* data,
                                                  size_t length,
                                                  rdp_xps_print_interface_query* query);
librdp_status rdp_xps_print_write_interface_query_response(rdp_buffer* buffer,
                                                           uint32_t interface_id,
                                                           uint32_t message_id,
                                                           const uint32_t* new_interface_id);
librdp_status rdp_xps_print_parse_interface_query_response(
    const void* data,
    size_t length,
    rdp_xps_print_interface_query_response* response);
librdp_status rdp_xps_print_parse_release(const void* data, size_t length, rdp_xps_print_header* header);
librdp_status rdp_xps_print_parse_xml_document(const void* data,
                                               size_t length,
                                               rdp_xps_print_xml_document* document);
librdp_status rdp_xps_print_write_xml_document(rdp_buffer* buffer, const void* data, uint32_t length);
librdp_status rdp_xps_print_parse_device_capability(const void* data,
                                                    size_t length,
                                                    rdp_xps_print_device_capability* capability);
librdp_status rdp_xps_print_write_device_capability(rdp_buffer* buffer,
                                                    uint32_t return_value,
                                                    uint32_t error_code,
                                                    const void* data,
                                                    uint16_t data_len);
librdp_status rdp_xps_print_parse_printer_property(const void* data,
                                                   size_t length,
                                                   rdp_xps_print_printer_property* property);
librdp_status rdp_xps_print_write_printer_property(rdp_buffer* buffer,
                                                   uint32_t property_type,
                                                   const void* name,
                                                   uint32_t name_len,
                                                   const void* value,
                                                   uint32_t value_len);
librdp_status rdp_xps_print_parse_u32_request(const void* data,
                                              size_t length,
                                              uint32_t function_id,
                                              rdp_xps_print_u32_request* request);
librdp_status rdp_xps_print_write_result(rdp_buffer* buffer,
                                         uint32_t interface_id,
                                         uint32_t message_id,
                                         uint32_t result);
librdp_status rdp_xps_print_parse_result(const void* data, size_t length, rdp_xps_print_result* result);
librdp_status rdp_xps_print_write_versions_response(rdp_buffer* buffer,
                                                    uint32_t interface_id,
                                                    uint32_t message_id,
                                                    const uint32_t* versions,
                                                    uint32_t version_count,
                                                    uint32_t result);
librdp_status rdp_xps_print_parse_versions_response(const void* data,
                                                    size_t length,
                                                    rdp_xps_print_versions_response* response);
librdp_status rdp_xps_print_write_blob_result(rdp_buffer* buffer,
                                              uint32_t interface_id,
                                              uint32_t message_id,
                                              const void* data,
                                              uint32_t data_len,
                                              uint32_t result);
librdp_status rdp_xps_print_parse_blob_result(const void* data,
                                              size_t length,
                                              rdp_xps_print_blob_result* result);
librdp_status rdp_xps_print_write_optional_blob_result(rdp_buffer* buffer,
                                                       uint32_t interface_id,
                                                       uint32_t message_id,
                                                       const void* data,
                                                       size_t data_len,
                                                       uint8_t null_flag,
                                                       uint32_t result);
librdp_status rdp_xps_print_parse_optional_blob_result(
    const void* data,
    size_t length,
    rdp_xps_print_optional_blob_result* result);

#endif
