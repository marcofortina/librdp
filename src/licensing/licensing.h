#ifndef RDP_LICENSING_LICENSING_H
#define RDP_LICENSING_LICENSING_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

typedef struct rdp_license_error_alert
{
    uint8_t message_type;
    uint8_t flags;
    uint16_t length;
    uint32_t error_code;
    uint32_t state_transition;
    uint16_t blob_type;
    uint16_t blob_length;
    const uint8_t* blob;
} rdp_license_error_alert;

librdp_status rdp_license_parse_error_alert(const void* data, size_t length, rdp_license_error_alert* alert);

#endif
