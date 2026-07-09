#ifndef RDP_CLIENT_SETTINGS_INTERNAL_H
#define RDP_CLIENT_SETTINGS_INTERNAL_H

#include <librdp/settings.h>

const char* rdp_settings_password_internal(const librdp_settings* settings);
uint32_t rdp_settings_drive_device_id_internal(const librdp_settings* settings, uint32_t index);
uint32_t rdp_settings_printer_device_id_internal(const librdp_settings* settings, uint32_t index);
uint32_t rdp_settings_smartcard_device_id_internal(const librdp_settings* settings, uint32_t index);
uint32_t rdp_settings_serial_port_device_id_internal(const librdp_settings* settings, uint32_t index);
uint32_t rdp_settings_parallel_port_device_id_internal(const librdp_settings* settings, uint32_t index);

#endif
