#ifndef RDP_TRANSPORT_MULTITRANSPORT_H
#define RDP_TRANSPORT_MULTITRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_MULTITRANSPORT_ACTION_CREATE_REQUEST 0x0u
#define RDP_MULTITRANSPORT_ACTION_CREATE_RESPONSE 0x1u
#define RDP_MULTITRANSPORT_ACTION_DATA 0x2u
#define RDP_MULTITRANSPORT_HEADER_LENGTH 4u
#define RDP_MULTITRANSPORT_COOKIE_LENGTH 16u

#define RDP_MULTITRANSPORT_SUBHEADER_AUTODETECT_REQUEST 0x00u
#define RDP_MULTITRANSPORT_SUBHEADER_AUTODETECT_RESPONSE 0x01u

typedef struct rdp_multitransport_header
{
    uint8_t action;
    uint8_t flags;
    uint16_t payload_length;
    uint8_t header_length;
    const uint8_t* subheaders;
    size_t subheaders_len;
    const uint8_t* payload;
    size_t payload_len;
} rdp_multitransport_header;

typedef struct rdp_multitransport_subheader
{
    uint8_t length;
    uint8_t type;
    const uint8_t* data;
    size_t data_len;
} rdp_multitransport_subheader;

typedef struct rdp_multitransport_create_request
{
    rdp_multitransport_header header;
    uint32_t request_id;
    uint32_t reserved;
    uint8_t security_cookie[RDP_MULTITRANSPORT_COOKIE_LENGTH];
} rdp_multitransport_create_request;

typedef struct rdp_multitransport_create_response
{
    rdp_multitransport_header header;
    uint32_t hresult;
} rdp_multitransport_create_response;

typedef struct rdp_multitransport_data
{
    rdp_multitransport_header header;
    const uint8_t* data;
    size_t data_len;
} rdp_multitransport_data;

librdp_status rdp_multitransport_parse_header(const void* data,
                                              size_t length,
                                              rdp_multitransport_header* header);
librdp_status rdp_multitransport_write_header(rdp_buffer* buffer,
                                              uint8_t action,
                                              const void* subheaders,
                                              size_t subheaders_len,
                                              size_t payload_len);
librdp_status rdp_multitransport_parse_subheader(const void* data,
                                                 size_t length,
                                                 rdp_multitransport_subheader* subheader);
librdp_status rdp_multitransport_count_subheaders(const void* data,
                                                  size_t length,
                                                  uint16_t* subheader_count);
librdp_status rdp_multitransport_write_subheader(rdp_buffer* buffer,
                                                 uint8_t type,
                                                 const void* data,
                                                 size_t data_len);
librdp_status rdp_multitransport_write_create_request(rdp_buffer* buffer,
                                                      uint32_t request_id,
                                                      const uint8_t security_cookie[RDP_MULTITRANSPORT_COOKIE_LENGTH]);
librdp_status rdp_multitransport_parse_create_request(
    const void* data,
    size_t length,
    rdp_multitransport_create_request* request);
librdp_status rdp_multitransport_write_create_response(rdp_buffer* buffer, uint32_t hresult);
librdp_status rdp_multitransport_parse_create_response(
    const void* data,
    size_t length,
    rdp_multitransport_create_response* response);
librdp_status rdp_multitransport_write_data(rdp_buffer* buffer,
                                            const void* subheaders,
                                            size_t subheaders_len,
                                            const void* data,
                                            size_t data_len);
librdp_status rdp_multitransport_parse_data(const void* data,
                                            size_t length,
                                            rdp_multitransport_data* tunnel_data);

#endif
