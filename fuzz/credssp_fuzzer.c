#include "nla/credssp.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_credssp_ts_request request;
    rdp_ntlm_challenge challenge;
    const uint8_t* ntlm = NULL;
    size_t ntlm_len = 0;

    (void)rdp_credssp_parse_ts_request(data, size, &request);
    (void)rdp_credssp_parse_ntlm_challenge(data, size, &challenge);
    if (rdp_credssp_extract_ntlm_challenge(data, size, &ntlm, &ntlm_len) == LIBRDP_STATUS_OK)
        (void)rdp_credssp_parse_ntlm_challenge(ntlm, ntlm_len, &challenge);
    return 0;
}
