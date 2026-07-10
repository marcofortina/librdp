#include "graphics/rfx_stream.h"

#include <stdint.h>
#include <stddef.h>

static librdp_status fuzz_rfx_stream_tile(const rdp_rfx_stream_tile* tile, void* user)
{
    (void)tile;
    (void)user;
    return LIBRDP_STATUS_OK;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_rfx_stream_summary summary;

    (void)rdp_rfx_stream_decode(data, size, fuzz_rfx_stream_tile, NULL, &summary);
    return 0;
}
