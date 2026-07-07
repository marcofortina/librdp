#ifndef RDP_NLA_CREDSSP_H
#define RDP_NLA_CREDSSP_H

#include <stdbool.h>

#include <librdp/error.h>

typedef enum rdp_credssp_state
{
    RDP_CREDSSP_DISABLED = 0,
    RDP_CREDSSP_NEGOTIATING = 1,
    RDP_CREDSSP_COMPLETE = 2,
    RDP_CREDSSP_FAILED = 3
} rdp_credssp_state;

librdp_status rdp_credssp_begin(bool enabled, rdp_credssp_state* state);

#endif
