#ifndef LIBRDP_SETTINGS_H
#define LIBRDP_SETTINGS_H

#include <stdint.h>

#include <librdp/error.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LIBRDP_SETTINGS_MAX_DRIVES 8u

typedef struct librdp_settings librdp_settings;

typedef enum librdp_security_mode
{
    LIBRDP_SECURITY_AUTO = 0,
    LIBRDP_SECURITY_STANDARD = 1,
    LIBRDP_SECURITY_TLS = 2,
    LIBRDP_SECURITY_NLA = 3
} librdp_security_mode;

librdp_settings* librdp_settings_new(void);
librdp_settings* librdp_settings_clone(const librdp_settings* settings);
void librdp_settings_free(librdp_settings* settings);
librdp_status librdp_settings_set_target(librdp_settings* settings, const char* target);
librdp_status librdp_settings_set_username(librdp_settings* settings, const char* username);
librdp_status librdp_settings_set_password(librdp_settings* settings, const char* password);
librdp_status librdp_settings_set_domain(librdp_settings* settings, const char* domain);
librdp_status librdp_settings_set_port(librdp_settings* settings, uint16_t port);
librdp_status librdp_settings_set_desktop_size(librdp_settings* settings, uint32_t width, uint32_t height);
librdp_status librdp_settings_set_security_mode(librdp_settings* settings, librdp_security_mode mode);
librdp_status librdp_settings_add_drive(librdp_settings* settings, const char* name, const char* path);
uint32_t librdp_settings_drive_count(const librdp_settings* settings);
const char* librdp_settings_drive_name(const librdp_settings* settings, uint32_t index);
const char* librdp_settings_drive_path(const librdp_settings* settings, uint32_t index);
const char* librdp_settings_target(const librdp_settings* settings);
const char* librdp_settings_username(const librdp_settings* settings);
const char* librdp_settings_domain(const librdp_settings* settings);
uint16_t librdp_settings_port(const librdp_settings* settings);
uint32_t librdp_settings_width(const librdp_settings* settings);
uint32_t librdp_settings_height(const librdp_settings* settings);
librdp_security_mode librdp_settings_security_mode(const librdp_settings* settings);

#ifdef __cplusplus
}
#endif

#endif
