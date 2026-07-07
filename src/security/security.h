#ifndef RDP_SECURITY_SECURITY_H
#define RDP_SECURITY_SECURITY_H

#include <stdbool.h>
#include <stdint.h>

#include <librdp/settings.h>

uint32_t rdp_security_protocol_mask(librdp_security_mode mode);
bool rdp_security_protocol_supported(uint32_t selected_protocol);

#endif
