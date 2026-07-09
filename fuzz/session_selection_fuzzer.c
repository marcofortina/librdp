#include "protocol/session_selection.h"

#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_session_selection_pdu pdu;
    rdp_buffer buffer;
    uint16_t chars = size > RDP_SESSION_SELECTION_MAX_TEXT_CHARS * 2u ?
        RDP_SESSION_SELECTION_MAX_TEXT_CHARS :
        (uint16_t)(size / 2u);

    (void)rdp_session_selection_parse_pdu(data, size, &pdu);
    rdp_buffer_init(&buffer);
    (void)rdp_session_selection_write_v1(&buffer, (uint32_t)size);
    buffer.length = 0;
    (void)rdp_session_selection_write_v2(&buffer, (uint32_t)size, data, chars);
    rdp_buffer_free(&buffer);
    return 0;
}
