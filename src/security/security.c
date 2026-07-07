#include "security/security.h"

#include "protocol/x224.h"

uint32_t rdp_security_protocol_mask(librdp_security_mode mode)
{
    switch (mode)
    {
        case LIBRDP_SECURITY_STANDARD:
            return RDP_X224_PROTOCOL_STANDARD;
        case LIBRDP_SECURITY_TLS:
            return RDP_X224_PROTOCOL_TLS;
        case LIBRDP_SECURITY_NLA:
            return RDP_X224_PROTOCOL_NLA;
        case LIBRDP_SECURITY_AUTO:
        default:
            return RDP_X224_PROTOCOL_TLS | RDP_X224_PROTOCOL_NLA;
    }
}

bool rdp_security_protocol_supported(uint32_t selected_protocol)
{
    return selected_protocol == RDP_X224_PROTOCOL_STANDARD;
}
