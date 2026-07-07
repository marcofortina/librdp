#ifndef RDP_SECURITY_SECURITY_H
#define RDP_SECURITY_SECURITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <librdp/settings.h>

#include "common/buffer.h"

#define RDP_SEC_EXCHANGE_PKT 0x0001u
#define RDP_SEC_INFO_PKT 0x0040u

typedef struct rdp_client_info
{
    const char* domain;
    const char* username;
    const char* password;
    const char* alternate_shell;
    const char* working_dir;
} rdp_client_info;

typedef struct rdp_client_info_summary
{
    uint32_t code_page;
    uint32_t flags;
    uint16_t domain_bytes;
    uint16_t username_bytes;
    uint16_t password_bytes;
    uint16_t alternate_shell_bytes;
    uint16_t working_dir_bytes;
} rdp_client_info_summary;

uint32_t rdp_security_protocol_mask(librdp_security_mode mode);
bool rdp_security_protocol_supported(uint32_t selected_protocol);
librdp_status rdp_security_write_header(rdp_buffer* buffer, uint16_t flags);
librdp_status rdp_security_write_exchange_pdu(rdp_buffer* buffer,
                                              const uint8_t* encrypted_client_random,
                                              size_t encrypted_client_random_len);
librdp_status rdp_security_write_client_info_pdu(rdp_buffer* buffer, const rdp_client_info* info);
librdp_status rdp_security_parse_client_info_pdu(const void* data,
                                                 size_t length,
                                                 rdp_client_info_summary* summary);
librdp_status rdp_security_write_send_data_request(rdp_buffer* buffer,
                                                   uint16_t user_id,
                                                   uint16_t channel_id,
                                                   const void* payload,
                                                   size_t payload_len);

#endif
