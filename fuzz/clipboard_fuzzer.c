#include "clipboard/clipboard.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_clipboard_packet packet;
    (void)rdp_clipboard_parse_packet(data, size, &packet);
    return 0;
}
