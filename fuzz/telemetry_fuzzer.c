#include "channels/telemetry.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_telemetry_pdu pdu;
    rdp_buffer buffer;

    (void)rdp_telemetry_parse_pdu(data, size, &pdu);
    rdp_buffer_init(&buffer);
    pdu.id = RDP_TELEMETRY_PDU_ID;
    pdu.length = RDP_TELEMETRY_PDU_LENGTH;
    pdu.prompt_for_credentials_ms = (uint32_t)size;
    pdu.prompt_for_credentials_done_ms = (uint32_t)(size >> 1);
    pdu.graphics_channel_opened_ms = (uint32_t)(size >> 2);
    pdu.first_graphics_received_ms = (uint32_t)(size >> 3);
    (void)rdp_telemetry_write_pdu(&buffer, &pdu);
    rdp_buffer_free(&buffer);
    return 0;
}
