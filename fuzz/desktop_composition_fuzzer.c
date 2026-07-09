#include "channels/desktop_composition.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_desktop_composition_header header;
    rdp_desktop_composition_toggle toggle;
    rdp_desktop_composition_lsurface lsurface;
    rdp_desktop_composition_surfobj surfobj;
    rdp_desktop_composition_assoc assoc;
    rdp_desktop_composition_u64_order u64_order;
    rdp_desktop_composition_u32_order u32_order;
    rdp_desktop_composition_opaque opaque;
    rdp_buffer buffer;
    uint16_t bounded = size > UINT16_MAX ? UINT16_MAX : (uint16_t)size;

    (void)rdp_desktop_composition_parse_header(data, size, &header);
    (void)rdp_desktop_composition_parse_toggle(data, size, &toggle);
    (void)rdp_desktop_composition_parse_lsurface(data, size, &lsurface);
    (void)rdp_desktop_composition_parse_surfobj(data, size, &surfobj);
    (void)rdp_desktop_composition_parse_assoc(data, size, &assoc);
    (void)rdp_desktop_composition_parse_compref(data, size, &u64_order);
    (void)rdp_desktop_composition_parse_switch_surfobj(data, size, &u32_order);
    (void)rdp_desktop_composition_parse_opaque(data, size, &opaque);

    rdp_buffer_init(&buffer);
    (void)rdp_desktop_composition_write_toggle(&buffer, RDP_DESKTOP_COMPOSITION_EVENT_COMPOSITION_ON);
    buffer.length = 0;
    (void)rdp_desktop_composition_write_lsurface(&buffer, 1, 0, 1, 0, 0, 2, 0);
    buffer.length = 0;
    (void)rdp_desktop_composition_write_surfobj(&buffer, 1, 32, 2, 640, 480);
    buffer.length = 0;
    (void)rdp_desktop_composition_write_assoc(&buffer, 1, 1, 2);
    buffer.length = 0;
    (void)rdp_desktop_composition_write_compref(&buffer, 1);
    buffer.length = 0;
    (void)rdp_desktop_composition_write_switch_surfobj(&buffer, 1);
    buffer.length = 0;
    (void)rdp_desktop_composition_write_opaque(&buffer, RDP_DESKTOP_COMPOSITION_OP_FLUSH_COMPOSE_ONCE, data, bounded);
    rdp_buffer_free(&buffer);
    return 0;
}
