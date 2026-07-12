/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for XPS print package and metadata parser paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "channels/xps_print.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises XPS print package and metadata parser paths with one
 * arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
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
    uint32_t bounded = size < 64u ? (uint32_t)size : 64u;
    uint32_t new_interface_id = 2;
    uint32_t int_value = 7;
    uint8_t guid[16] = {0};
    const uint8_t name[] = {'N', 0};

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
    (void)rdp_xps_print_write_header(&buffer, 0, 1, 1, RDP_XPS_PRINT_FUNC_QUERY_INTERFACE);
    buffer.length = 0;
    (void)rdp_xps_print_write_interface_query(&buffer, 0, 1, guid);
    buffer.length = 0;
    (void)rdp_xps_print_write_interface_query_response(&buffer, 0, 1, &new_interface_id);
    buffer.length = 0;
    (void)rdp_xps_print_write_interface_query_response(&buffer, 0, 1, NULL);
    buffer.length = 0;
    (void)rdp_xps_print_write_release(&buffer, 0, 1);
    buffer.length = 0;
    (void)rdp_xps_print_write_u32_request(&buffer, 1, RDP_XPS_PRINT_DRIVER_INIT_PRINTER, 0);
    buffer.length = 0;
    (void)rdp_xps_print_write_xml_document(&buffer, data, bounded);
    buffer.length = 0;
    (void)rdp_xps_print_write_device_capability(&buffer, 0, 0, data, (uint16_t)bounded);
    buffer.length = 0;
    (void)rdp_xps_print_write_printer_property(&buffer,
                                               RDP_XPS_PRINT_PROPERTY_INT32,
                                               name,
                                               (uint32_t)sizeof(name),
                                               &int_value,
                                               (uint32_t)sizeof(int_value));
    buffer.length = 0;
    (void)rdp_xps_print_write_printer_property(&buffer,
                                               RDP_XPS_PRINT_PROPERTY_BUFFER,
                                               name,
                                               (uint32_t)sizeof(name),
                                               data,
                                               bounded);
    buffer.length = 0;
    (void)rdp_xps_print_write_result(&buffer, 0, 1, 0);
    buffer.length = 0;
    (void)rdp_xps_print_write_versions_response(&buffer, 0, 1, &version, 1, 0);
    buffer.length = 0;
    (void)rdp_xps_print_write_blob_result(&buffer, 0, 1, data, bounded, 0);
    buffer.length = 0;
    (void)rdp_xps_print_write_optional_blob_result(&buffer,
                                                   0,
                                                   1,
                                                   data,
                                                   bounded,
                                                   RDP_XPS_PRINT_NULL_PRESENT,
                                                   0);
    buffer.length = 0;
    (void)rdp_xps_print_write_optional_blob_result(&buffer, 0, 1, NULL, 0, RDP_XPS_PRINT_NULL_ABSENT, 0);
    rdp_buffer_free(&buffer);
    return 0;
}
