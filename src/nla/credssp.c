#include "nla/credssp.h"

librdp_status rdp_credssp_begin(bool enabled, rdp_credssp_state* state)
{
    if (!state)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!enabled)
    {
        *state = RDP_CREDSSP_DISABLED;
        return LIBRDP_STATUS_OK;
    }
    *state = RDP_CREDSSP_FAILED;
    return LIBRDP_STATUS_UNSUPPORTED;
}
