#ifndef LIBRDP_SETTINGS_H
#define LIBRDP_SETTINGS_H

#include <stdint.h>

#include <librdp/error.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LIBRDP_SETTINGS_MAX_DRIVES 8u
#define LIBRDP_SETTINGS_MAX_PRINTERS 8u
#define LIBRDP_SETTINGS_MAX_CAMERAS 8u
#define LIBRDP_SETTINGS_MAX_SMARTCARDS 8u
#define LIBRDP_SETTINGS_MAX_USB_DEVICES 16u
#define LIBRDP_SETTINGS_MAX_RAIL_APPS 16u
#define LIBRDP_SETTINGS_MAX_SERIAL_PORTS 8u
#define LIBRDP_SETTINGS_MAX_PARALLEL_PORTS 8u

typedef struct librdp_settings librdp_settings;

typedef enum librdp_security_mode
{
    LIBRDP_SECURITY_AUTO = 0,
    LIBRDP_SECURITY_STANDARD = 1,
    LIBRDP_SECURITY_TLS = 2,
    LIBRDP_SECURITY_NLA = 3
} librdp_security_mode;

typedef enum librdp_feature
{
    LIBRDP_FEATURE_AUDIO_OUTPUT = 0x00000001u,
    LIBRDP_FEATURE_AUDIO_INPUT = 0x00000002u,
    LIBRDP_FEATURE_VIDEO = 0x00000004u,
    LIBRDP_FEATURE_CAMERA = 0x00000008u,
    LIBRDP_FEATURE_SMARTCARD = 0x00000010u,
    LIBRDP_FEATURE_USB = 0x00000020u,
    LIBRDP_FEATURE_PNP = 0x00000040u,
    LIBRDP_FEATURE_WEBAUTHN = 0x00000080u,
    LIBRDP_FEATURE_RAIL = 0x00000100u,
    LIBRDP_FEATURE_CR2 = 0x00000200u,
    LIBRDP_FEATURE_ECHO = 0x00000400u,
    LIBRDP_FEATURE_TELEMETRY = 0x00000800u
} librdp_feature;

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
librdp_status librdp_settings_add_serial_port(librdp_settings* settings,
                                              const char* name,
                                              const char* path);
librdp_status librdp_settings_add_parallel_port(librdp_settings* settings,
                                                const char* name,
                                                const char* path);
librdp_status librdp_settings_add_printer(librdp_settings* settings,
                                          const char* name,
                                          const char* driver,
                                          const char* output_path);
librdp_status librdp_settings_enable_feature(librdp_settings* settings,
                                             librdp_feature feature,
                                             int enabled);
int librdp_settings_feature_enabled(const librdp_settings* settings, librdp_feature feature);
librdp_status librdp_settings_set_audio_output_device(librdp_settings* settings, const char* device);
librdp_status librdp_settings_set_audio_input_device(librdp_settings* settings, const char* device);
librdp_status librdp_settings_set_video_output_path(librdp_settings* settings, const char* path);
librdp_status librdp_settings_add_camera(librdp_settings* settings, const char* source);
librdp_status librdp_settings_add_smartcard(librdp_settings* settings, const char* source);
librdp_status librdp_settings_add_usb_device(librdp_settings* settings, const char* selector);
librdp_status librdp_settings_set_webauthn_provider(librdp_settings* settings, const char* provider);
librdp_status librdp_settings_add_rail_app(librdp_settings* settings, const char* app);
librdp_status librdp_settings_set_echo_payload(librdp_settings* settings, const char* payload);
uint32_t librdp_settings_drive_count(const librdp_settings* settings);
const char* librdp_settings_drive_name(const librdp_settings* settings, uint32_t index);
const char* librdp_settings_drive_path(const librdp_settings* settings, uint32_t index);
uint32_t librdp_settings_serial_port_count(const librdp_settings* settings);
const char* librdp_settings_serial_port_name(const librdp_settings* settings, uint32_t index);
const char* librdp_settings_serial_port_path(const librdp_settings* settings, uint32_t index);
uint32_t librdp_settings_parallel_port_count(const librdp_settings* settings);
const char* librdp_settings_parallel_port_name(const librdp_settings* settings, uint32_t index);
const char* librdp_settings_parallel_port_path(const librdp_settings* settings, uint32_t index);
uint32_t librdp_settings_printer_count(const librdp_settings* settings);
const char* librdp_settings_printer_name(const librdp_settings* settings, uint32_t index);
const char* librdp_settings_printer_driver(const librdp_settings* settings, uint32_t index);
const char* librdp_settings_printer_output_path(const librdp_settings* settings, uint32_t index);
const char* librdp_settings_audio_output_device(const librdp_settings* settings);
const char* librdp_settings_audio_input_device(const librdp_settings* settings);
const char* librdp_settings_video_output_path(const librdp_settings* settings);
uint32_t librdp_settings_camera_count(const librdp_settings* settings);
const char* librdp_settings_camera_source(const librdp_settings* settings, uint32_t index);
uint32_t librdp_settings_smartcard_count(const librdp_settings* settings);
const char* librdp_settings_smartcard_source(const librdp_settings* settings, uint32_t index);
uint32_t librdp_settings_usb_device_count(const librdp_settings* settings);
const char* librdp_settings_usb_device_selector(const librdp_settings* settings, uint32_t index);
const char* librdp_settings_webauthn_provider(const librdp_settings* settings);
uint32_t librdp_settings_rail_app_count(const librdp_settings* settings);
const char* librdp_settings_rail_app(const librdp_settings* settings, uint32_t index);
const char* librdp_settings_echo_payload(const librdp_settings* settings);
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
