#include "channels/remote_programs.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_remote_programs_header header;
    rdp_remote_programs_u32_order u32_order;
    rdp_remote_programs_handshake_ex handshake_ex;
    rdp_remote_programs_exec exec;
    rdp_remote_programs_exec_result result;
    rdp_remote_programs_activate activate;
    rdp_remote_programs_opaque opaque;
    rdp_buffer buffer;
    uint16_t bounded_path = size > RDP_REMOTE_PROGRAMS_MAX_EXEC_PATH_BYTES ?
        RDP_REMOTE_PROGRAMS_MAX_EXEC_PATH_BYTES :
        (uint16_t)size;
    size_t bounded_payload = size > RDP_REMOTE_PROGRAMS_MAX_PDU_BYTES - 4u ?
        RDP_REMOTE_PROGRAMS_MAX_PDU_BYTES - 4u :
        size;

    (void)rdp_remote_programs_parse_header(data, size, &header);
    (void)rdp_remote_programs_parse_u32_order(data, size, RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE, &u32_order);
    (void)rdp_remote_programs_parse_handshake_ex(data, size, &handshake_ex);
    (void)rdp_remote_programs_parse_exec(data, size, &exec);
    (void)rdp_remote_programs_parse_exec_result(data, size, &result);
    (void)rdp_remote_programs_parse_activate(data, size, &activate);
    (void)rdp_remote_programs_parse_opaque(data, size, &opaque);

    rdp_buffer_init(&buffer);
    (void)rdp_remote_programs_write_u32_order(&buffer, RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE, (uint32_t)size);
    buffer.length = 0;
    (void)rdp_remote_programs_write_handshake_ex(&buffer, (uint32_t)size, 0);
    buffer.length = 0;
    if (bounded_path > 0)
        (void)rdp_remote_programs_write_exec(&buffer, 0, data, bounded_path, NULL, 0, NULL, 0);
    buffer.length = 0;
    if (bounded_path > 0)
        (void)rdp_remote_programs_write_exec_result(&buffer,
                                                    0,
                                                    RDP_REMOTE_PROGRAMS_EXEC_RESULT_OK,
                                                    0,
                                                    data,
                                                    bounded_path);
    buffer.length = 0;
    (void)rdp_remote_programs_write_activate(&buffer, (uint32_t)size, 1);
    buffer.length = 0;
    (void)rdp_remote_programs_write_opaque(&buffer, RDP_REMOTE_PROGRAMS_ORDER_SYSPARAM, data, bounded_payload);
    rdp_buffer_free(&buffer);
    return 0;
}
