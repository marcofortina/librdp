#include "channels/xps_print.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_xps_print_header header;
    rdp_xps_print_interface_query query;
    rdp_xps_print_interface_query_response query_response;
    rdp_xps_print_xml_document document;
    rdp_xps_print_device_capability capability;
    rdp_xps_print_printer_property property;
    rdp_xps_print_u32_request request;
    rdp_xps_print_versions_response versions;
    rdp_xps_print_blob_result blob_result;
    rdp_xps_print_optional_blob_result optional_result;
    rdp_xps_print_result result;
    rdp_buffer buffer;
    uint32_t version = 1;

    (void)rdp_xps_print_parse_header(data, size, 0, &header);
    (void)rdp_xps_print_parse_header(data, size, 1, &header);
    (void)rdp_xps_print_parse_interface_query(data, size, &query);
    (void)rdp_xps_print_parse_interface_query_response(data, size, &query_response);
    (void)rdp_xps_print_parse_release(data, size, &header);
    (void)rdp_xps_print_parse_xml_document(data, size, &document);
    (void)rdp_xps_print_parse_device_capability(data, size, &capability);
    (void)rdp_xps_print_parse_printer_property(data, size, &property);
    (void)rdp_xps_print_parse_u32_request(data, size, RDP_XPS_PRINT_DRIVER_INIT_PRINTER, &request);
    (void)rdp_xps_print_parse_result(data, size, &result);
    (void)rdp_xps_print_parse_versions_response(data, size, &versions);
    (void)rdp_xps_print_parse_blob_result(data, size, &blob_result);
    (void)rdp_xps_print_parse_optional_blob_result(data, size, &optional_result);

    rdp_buffer_init(&buffer);
    (void)rdp_xps_print_write_xml_document(&buffer, data, size > UINT32_MAX ? UINT32_MAX : (uint32_t)size);
    buffer.length = 0;
    (void)rdp_xps_print_write_versions_response(&buffer, 0, 1, &version, 1, 0);
    buffer.length = 0;
    (void)rdp_xps_print_write_optional_blob_result(&buffer, 0, 1, NULL, 0, RDP_XPS_PRINT_NULL_ABSENT, 0);
    rdp_buffer_free(&buffer);
    return 0;
}
