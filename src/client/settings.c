#include <librdp/settings.h>

#include "client/settings_internal.h"

#include <stdlib.h>
#include <string.h>

typedef struct rdp_settings_drive
{
    char name[8];
    char* path;
} rdp_settings_drive;

typedef struct rdp_settings_port
{
    char name[8];
    char* path;
} rdp_settings_port;

typedef struct rdp_settings_printer
{
    char* name;
    char* driver;
    char* output_path;
} rdp_settings_printer;

typedef struct rdp_settings_pnp_device
{
    char* hardware_id;
    char* compatibility_id;
    char* description;
    uint32_t device_caps;
} rdp_settings_pnp_device;

struct librdp_settings
{
    char* target;
    char* username;
    char* password;
    char* domain;
    char* audio_output_device;
    char* audio_input_device;
    char* video_output_path;
    char* webauthn_provider;
    char* echo_payload;
    uint16_t port;
    uint32_t width;
    uint32_t height;
    uint32_t features;
    librdp_security_mode security_mode;
    uint32_t drive_count;
    rdp_settings_drive drives[LIBRDP_SETTINGS_MAX_DRIVES];
    uint32_t serial_port_count;
    rdp_settings_port serial_ports[LIBRDP_SETTINGS_MAX_SERIAL_PORTS];
    uint32_t parallel_port_count;
    rdp_settings_port parallel_ports[LIBRDP_SETTINGS_MAX_PARALLEL_PORTS];
    uint32_t printer_count;
    rdp_settings_printer printers[LIBRDP_SETTINGS_MAX_PRINTERS];
    uint32_t camera_count;
    char* cameras[LIBRDP_SETTINGS_MAX_CAMERAS];
    uint32_t smartcard_count;
    char* smartcards[LIBRDP_SETTINGS_MAX_SMARTCARDS];
    uint32_t usb_device_count;
    char* usb_devices[LIBRDP_SETTINGS_MAX_USB_DEVICES];
    uint32_t rail_app_count;
    char* rail_apps[LIBRDP_SETTINGS_MAX_RAIL_APPS];
    uint32_t pnp_device_count;
    rdp_settings_pnp_device pnp_devices[LIBRDP_SETTINGS_MAX_PNP_DEVICES];
};

#define RDP_SETTINGS_TEXT_MAX 4096u

static char* rdp_strdup(const char* value)
{
    size_t length = 0;
    char* out = NULL;

    if (!value)
        return NULL;

    length = strlen(value) + 1;
    out = (char*)malloc(length);
    if (!out)
        return NULL;
    memcpy(out, value, length);
    return out;
}

static librdp_status rdp_set_string(char** field, const char* value)
{
    char* copy = NULL;

    if (!field)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    if (value)
    {
        copy = rdp_strdup(value);
        if (!copy)
            return LIBRDP_STATUS_NO_MEMORY;
    }

    free(*field);
    *field = copy;
    return LIBRDP_STATUS_OK;
}

static int rdp_settings_valid_drive_name(const char* name)
{
    size_t i = 0;
    size_t length = 0;

    if (!name || name[0] == '\0')
        return 0;
    length = strlen(name);
    if (length > 7u)
        return 0;
    for (i = 0; i < length; i++)
    {
        if (name[i] == '<' || name[i] == '>' || name[i] == '"' ||
            name[i] == '/' || name[i] == '\\' || name[i] == '|')
            return 0;
        if (name[i] == ':' && i + 1u != length)
            return 0;
    }
    return 1;
}

static int rdp_settings_valid_port_name(const char* name)
{
    return rdp_settings_valid_drive_name(name);
}

static int rdp_settings_valid_printer_text(const char* value)
{
    size_t length = 0;

    if (!value || value[0] == '\0')
        return 0;
    length = strlen(value);
    return length <= 127u;
}

static int rdp_settings_valid_text(const char* value)
{
    size_t length = 0;

    if (!value || value[0] == '\0')
        return 0;
    length = strlen(value);
    return length <= RDP_SETTINGS_TEXT_MAX;
}

static int rdp_settings_valid_webauthn_provider(const char* value)
{
    if (!value)
        return 1;
    if (strcmp(value, "mock") == 0)
        return 1;
    return strncmp(value, "mock=", 5u) == 0 && value[5] != '\0' &&
           strlen(value) <= RDP_SETTINGS_TEXT_MAX;
}

static librdp_status rdp_settings_add_text(char** values,
                                           uint32_t* count,
                                           uint32_t limit,
                                           const char* value)
{
    char* copy = NULL;

    if (!values || !count || !rdp_settings_valid_text(value) || *count >= limit)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    copy = rdp_strdup(value);
    if (!copy)
        return LIBRDP_STATUS_NO_MEMORY;
    values[*count] = copy;
    *count += 1u;
    return LIBRDP_STATUS_OK;
}

librdp_settings* librdp_settings_new(void)
{
    librdp_settings* settings = (librdp_settings*)calloc(1, sizeof(*settings));

    if (!settings)
        return NULL;

    settings->port = 3389;
    settings->width = 1024;
    settings->height = 768;
    settings->security_mode = LIBRDP_SECURITY_AUTO;
    return settings;
}

librdp_settings* librdp_settings_clone(const librdp_settings* settings)
{
    librdp_settings* copy = NULL;

    if (!settings)
        return NULL;

    copy = librdp_settings_new();
    if (!copy)
        return NULL;

    copy->port = settings->port;
    copy->width = settings->width;
    copy->height = settings->height;
    copy->features = settings->features;
    copy->security_mode = settings->security_mode;

    if ((settings->target && librdp_settings_set_target(copy, settings->target) != LIBRDP_STATUS_OK) ||
        (settings->username && librdp_settings_set_username(copy, settings->username) != LIBRDP_STATUS_OK) ||
        (settings->password && librdp_settings_set_password(copy, settings->password) != LIBRDP_STATUS_OK) ||
        (settings->domain && librdp_settings_set_domain(copy, settings->domain) != LIBRDP_STATUS_OK) ||
        (settings->audio_output_device &&
         librdp_settings_set_audio_output_device(copy, settings->audio_output_device) != LIBRDP_STATUS_OK) ||
        (settings->audio_input_device &&
         librdp_settings_set_audio_input_device(copy, settings->audio_input_device) != LIBRDP_STATUS_OK) ||
        (settings->video_output_path &&
         librdp_settings_set_video_output_path(copy, settings->video_output_path) != LIBRDP_STATUS_OK) ||
        (settings->webauthn_provider &&
         librdp_settings_set_webauthn_provider(copy, settings->webauthn_provider) != LIBRDP_STATUS_OK) ||
        (settings->echo_payload &&
         librdp_settings_set_echo_payload(copy, settings->echo_payload) != LIBRDP_STATUS_OK))
    {
        librdp_settings_free(copy);
        return NULL;
    }
    for (uint32_t i = 0; i < settings->drive_count; i++)
    {
        if (librdp_settings_add_drive(copy, settings->drives[i].name, settings->drives[i].path) !=
            LIBRDP_STATUS_OK)
        {
            librdp_settings_free(copy);
            return NULL;
        }
    }
    for (uint32_t i = 0; i < settings->serial_port_count; i++)
    {
        if (librdp_settings_add_serial_port(copy,
                                            settings->serial_ports[i].name,
                                            settings->serial_ports[i].path) != LIBRDP_STATUS_OK)
        {
            librdp_settings_free(copy);
            return NULL;
        }
    }
    for (uint32_t i = 0; i < settings->parallel_port_count; i++)
    {
        if (librdp_settings_add_parallel_port(copy,
                                              settings->parallel_ports[i].name,
                                              settings->parallel_ports[i].path) != LIBRDP_STATUS_OK)
        {
            librdp_settings_free(copy);
            return NULL;
        }
    }
    for (uint32_t i = 0; i < settings->printer_count; i++)
    {
        if (librdp_settings_add_printer(copy,
                                        settings->printers[i].name,
                                        settings->printers[i].driver,
                                        settings->printers[i].output_path) != LIBRDP_STATUS_OK)
        {
            librdp_settings_free(copy);
            return NULL;
        }
    }
    for (uint32_t i = 0; i < settings->camera_count; i++)
    {
        if (librdp_settings_add_camera(copy, settings->cameras[i]) != LIBRDP_STATUS_OK)
        {
            librdp_settings_free(copy);
            return NULL;
        }
    }
    for (uint32_t i = 0; i < settings->smartcard_count; i++)
    {
        if (librdp_settings_add_smartcard(copy, settings->smartcards[i]) != LIBRDP_STATUS_OK)
        {
            librdp_settings_free(copy);
            return NULL;
        }
    }
    for (uint32_t i = 0; i < settings->usb_device_count; i++)
    {
        if (librdp_settings_add_usb_device(copy, settings->usb_devices[i]) != LIBRDP_STATUS_OK)
        {
            librdp_settings_free(copy);
            return NULL;
        }
    }
    for (uint32_t i = 0; i < settings->pnp_device_count; i++)
    {
        if (librdp_settings_add_pnp_device(copy,
                                           settings->pnp_devices[i].hardware_id,
                                           settings->pnp_devices[i].compatibility_id,
                                           settings->pnp_devices[i].description,
                                           settings->pnp_devices[i].device_caps) != LIBRDP_STATUS_OK)
        {
            librdp_settings_free(copy);
            return NULL;
        }
    }
    for (uint32_t i = 0; i < settings->rail_app_count; i++)
    {
        if (librdp_settings_add_rail_app(copy, settings->rail_apps[i]) != LIBRDP_STATUS_OK)
        {
            librdp_settings_free(copy);
            return NULL;
        }
    }

    return copy;
}

void librdp_settings_free(librdp_settings* settings)
{
    if (!settings)
        return;

    free(settings->target);
    free(settings->username);
    free(settings->password);
    free(settings->domain);
    free(settings->audio_output_device);
    free(settings->audio_input_device);
    free(settings->video_output_path);
    free(settings->webauthn_provider);
    free(settings->echo_payload);
    for (uint32_t i = 0; i < settings->drive_count; i++)
        free(settings->drives[i].path);
    for (uint32_t i = 0; i < settings->serial_port_count; i++)
        free(settings->serial_ports[i].path);
    for (uint32_t i = 0; i < settings->parallel_port_count; i++)
        free(settings->parallel_ports[i].path);
    for (uint32_t i = 0; i < settings->printer_count; i++)
    {
        free(settings->printers[i].name);
        free(settings->printers[i].driver);
        free(settings->printers[i].output_path);
    }
    for (uint32_t i = 0; i < settings->camera_count; i++)
        free(settings->cameras[i]);
    for (uint32_t i = 0; i < settings->smartcard_count; i++)
        free(settings->smartcards[i]);
    for (uint32_t i = 0; i < settings->usb_device_count; i++)
        free(settings->usb_devices[i]);
    for (uint32_t i = 0; i < settings->pnp_device_count; i++)
    {
        free(settings->pnp_devices[i].hardware_id);
        free(settings->pnp_devices[i].compatibility_id);
        free(settings->pnp_devices[i].description);
    }
    for (uint32_t i = 0; i < settings->rail_app_count; i++)
        free(settings->rail_apps[i]);
    free(settings);
}

librdp_status librdp_settings_set_target(librdp_settings* settings, const char* target)
{
    if (!settings || !target || target[0] == '\0')
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_set_string(&settings->target, target);
}

librdp_status librdp_settings_set_username(librdp_settings* settings, const char* username)
{
    if (!settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_set_string(&settings->username, username);
}

librdp_status librdp_settings_set_password(librdp_settings* settings, const char* password)
{
    if (!settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_set_string(&settings->password, password);
}

librdp_status librdp_settings_set_domain(librdp_settings* settings, const char* domain)
{
    if (!settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_set_string(&settings->domain, domain);
}

librdp_status librdp_settings_set_port(librdp_settings* settings, uint16_t port)
{
    if (!settings || port == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    settings->port = port;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_settings_set_desktop_size(librdp_settings* settings, uint32_t width, uint32_t height)
{
    if (!settings || width == 0 || height == 0 || width > 8192 || height > 8192)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    settings->width = width;
    settings->height = height;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_settings_set_security_mode(librdp_settings* settings, librdp_security_mode mode)
{
    if (!settings || mode < LIBRDP_SECURITY_AUTO || mode > LIBRDP_SECURITY_NLA)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    settings->security_mode = mode;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_settings_add_drive(librdp_settings* settings, const char* name, const char* path)
{
    char* path_copy = NULL;
    rdp_settings_drive* drive = NULL;

    if (!settings || !rdp_settings_valid_drive_name(name) || !path || path[0] == '\0' ||
        settings->drive_count >= LIBRDP_SETTINGS_MAX_DRIVES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    path_copy = rdp_strdup(path);
    if (!path_copy)
        return LIBRDP_STATUS_NO_MEMORY;
    drive = &settings->drives[settings->drive_count];
    memset(drive, 0, sizeof(*drive));
    memcpy(drive->name, name, strlen(name) + 1u);
    drive->path = path_copy;
    settings->drive_count++;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_settings_add_port(rdp_settings_port* ports,
                                           uint32_t* count,
                                           uint32_t limit,
                                           const char* name,
                                           const char* path)
{
    char* path_copy = NULL;
    rdp_settings_port* port = NULL;

    if (!ports || !count || !rdp_settings_valid_port_name(name) || !path || path[0] == '\0' ||
        *count >= limit)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    path_copy = rdp_strdup(path);
    if (!path_copy)
        return LIBRDP_STATUS_NO_MEMORY;
    port = &ports[*count];
    memset(port, 0, sizeof(*port));
    memcpy(port->name, name, strlen(name) + 1u);
    port->path = path_copy;
    *count += 1u;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_settings_add_serial_port(librdp_settings* settings,
                                              const char* name,
                                              const char* path)
{
    if (!settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_settings_add_port(settings->serial_ports,
                                 &settings->serial_port_count,
                                 LIBRDP_SETTINGS_MAX_SERIAL_PORTS,
                                 name,
                                 path);
}

librdp_status librdp_settings_add_parallel_port(librdp_settings* settings,
                                                const char* name,
                                                const char* path)
{
    if (!settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_settings_add_port(settings->parallel_ports,
                                 &settings->parallel_port_count,
                                 LIBRDP_SETTINGS_MAX_PARALLEL_PORTS,
                                 name,
                                 path);
}

librdp_status librdp_settings_add_printer(librdp_settings* settings,
                                          const char* name,
                                          const char* driver,
                                          const char* output_path)
{
    rdp_settings_printer* printer = NULL;
    char* name_copy = NULL;
    char* driver_copy = NULL;
    char* output_copy = NULL;

    if (!settings || !rdp_settings_valid_printer_text(name) ||
        !rdp_settings_valid_printer_text(driver) || !output_path || output_path[0] == '\0' ||
        settings->printer_count >= LIBRDP_SETTINGS_MAX_PRINTERS)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    name_copy = rdp_strdup(name);
    driver_copy = rdp_strdup(driver);
    output_copy = rdp_strdup(output_path);
    if (!name_copy || !driver_copy || !output_copy)
    {
        free(name_copy);
        free(driver_copy);
        free(output_copy);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    printer = &settings->printers[settings->printer_count];
    printer->name = name_copy;
    printer->driver = driver_copy;
    printer->output_path = output_copy;
    settings->printer_count++;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_settings_enable_feature(librdp_settings* settings,
                                             librdp_feature feature,
                                             int enabled)
{
    if (!settings || feature == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (enabled)
        settings->features |= (uint32_t)feature;
    else
        settings->features &= ~((uint32_t)feature);
    return LIBRDP_STATUS_OK;
}

int librdp_settings_feature_enabled(const librdp_settings* settings, librdp_feature feature)
{
    if (!settings || feature == 0)
        return 0;
    return (settings->features & (uint32_t)feature) != 0;
}

librdp_status librdp_settings_set_audio_output_device(librdp_settings* settings, const char* device)
{
    if (!settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (device && !rdp_settings_valid_text(device))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_set_string(&settings->audio_output_device, device);
}

librdp_status librdp_settings_set_audio_input_device(librdp_settings* settings, const char* device)
{
    if (!settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (device && !rdp_settings_valid_text(device))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_set_string(&settings->audio_input_device, device);
}

librdp_status librdp_settings_set_video_output_path(librdp_settings* settings, const char* path)
{
    if (!settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (path && !rdp_settings_valid_text(path))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_set_string(&settings->video_output_path, path);
}

librdp_status librdp_settings_add_camera(librdp_settings* settings, const char* source)
{
    if (!settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_settings_add_text(settings->cameras,
                                 &settings->camera_count,
                                 LIBRDP_SETTINGS_MAX_CAMERAS,
                                 source);
}

librdp_status librdp_settings_add_smartcard(librdp_settings* settings, const char* source)
{
    if (!settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_settings_add_text(settings->smartcards,
                                 &settings->smartcard_count,
                                 LIBRDP_SETTINGS_MAX_SMARTCARDS,
                                 source);
}

librdp_status librdp_settings_add_usb_device(librdp_settings* settings, const char* selector)
{
    if (!settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_settings_add_text(settings->usb_devices,
                                 &settings->usb_device_count,
                                 LIBRDP_SETTINGS_MAX_USB_DEVICES,
                                 selector);
}

librdp_status librdp_settings_add_pnp_device(librdp_settings* settings,
                                             const char* hardware_id,
                                             const char* compatibility_id,
                                             const char* description,
                                             uint32_t device_caps)
{
    rdp_settings_pnp_device* device = NULL;
    char* hardware_copy = NULL;
    char* compatibility_copy = NULL;
    char* description_copy = NULL;

    if (!settings || !rdp_settings_valid_text(hardware_id) ||
        !rdp_settings_valid_text(compatibility_id) ||
        !rdp_settings_valid_text(description) ||
        (device_caps & ~(LIBRDP_PNP_DEVICE_CAP_LOCK_SUPPORTED |
                         LIBRDP_PNP_DEVICE_CAP_EJECT_SUPPORTED |
                         LIBRDP_PNP_DEVICE_CAP_REMOVABLE |
                         LIBRDP_PNP_DEVICE_CAP_SURPRISE_REMOVAL_OK)) != 0 ||
        settings->pnp_device_count >= LIBRDP_SETTINGS_MAX_PNP_DEVICES)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    hardware_copy = rdp_strdup(hardware_id);
    compatibility_copy = rdp_strdup(compatibility_id);
    description_copy = rdp_strdup(description);
    if (!hardware_copy || !compatibility_copy || !description_copy)
    {
        free(hardware_copy);
        free(compatibility_copy);
        free(description_copy);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    device = &settings->pnp_devices[settings->pnp_device_count++];
    memset(device, 0, sizeof(*device));
    device->hardware_id = hardware_copy;
    device->compatibility_id = compatibility_copy;
    device->description = description_copy;
    device->device_caps = device_caps;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_settings_set_webauthn_provider(librdp_settings* settings, const char* provider)
{
    if (!settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_settings_valid_webauthn_provider(provider))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_set_string(&settings->webauthn_provider, provider);
}

librdp_status librdp_settings_add_rail_app(librdp_settings* settings, const char* app)
{
    if (!settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_settings_add_text(settings->rail_apps,
                                 &settings->rail_app_count,
                                 LIBRDP_SETTINGS_MAX_RAIL_APPS,
                                 app);
}

librdp_status librdp_settings_set_echo_payload(librdp_settings* settings, const char* payload)
{
    if (!settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (payload && !rdp_settings_valid_text(payload))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_set_string(&settings->echo_payload, payload);
}

uint32_t librdp_settings_drive_count(const librdp_settings* settings)
{
    return settings ? settings->drive_count : 0;
}

const char* librdp_settings_drive_name(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->drive_count)
        return NULL;
    return settings->drives[index].name;
}

const char* librdp_settings_drive_path(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->drive_count)
        return NULL;
    return settings->drives[index].path;
}

uint32_t librdp_settings_serial_port_count(const librdp_settings* settings)
{
    return settings ? settings->serial_port_count : 0;
}

const char* librdp_settings_serial_port_name(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->serial_port_count)
        return NULL;
    return settings->serial_ports[index].name;
}

const char* librdp_settings_serial_port_path(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->serial_port_count)
        return NULL;
    return settings->serial_ports[index].path;
}

uint32_t librdp_settings_parallel_port_count(const librdp_settings* settings)
{
    return settings ? settings->parallel_port_count : 0;
}

const char* librdp_settings_parallel_port_name(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->parallel_port_count)
        return NULL;
    return settings->parallel_ports[index].name;
}

const char* librdp_settings_parallel_port_path(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->parallel_port_count)
        return NULL;
    return settings->parallel_ports[index].path;
}

uint32_t librdp_settings_printer_count(const librdp_settings* settings)
{
    return settings ? settings->printer_count : 0;
}

const char* librdp_settings_printer_name(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->printer_count)
        return NULL;
    return settings->printers[index].name;
}

const char* librdp_settings_printer_driver(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->printer_count)
        return NULL;
    return settings->printers[index].driver;
}

const char* librdp_settings_printer_output_path(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->printer_count)
        return NULL;
    return settings->printers[index].output_path;
}

const char* librdp_settings_audio_output_device(const librdp_settings* settings)
{
    return settings ? settings->audio_output_device : NULL;
}

const char* librdp_settings_audio_input_device(const librdp_settings* settings)
{
    return settings ? settings->audio_input_device : NULL;
}

const char* librdp_settings_video_output_path(const librdp_settings* settings)
{
    return settings ? settings->video_output_path : NULL;
}

uint32_t librdp_settings_camera_count(const librdp_settings* settings)
{
    return settings ? settings->camera_count : 0;
}

const char* librdp_settings_camera_source(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->camera_count)
        return NULL;
    return settings->cameras[index];
}

uint32_t librdp_settings_smartcard_count(const librdp_settings* settings)
{
    return settings ? settings->smartcard_count : 0;
}

const char* librdp_settings_smartcard_source(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->smartcard_count)
        return NULL;
    return settings->smartcards[index];
}

uint32_t librdp_settings_usb_device_count(const librdp_settings* settings)
{
    return settings ? settings->usb_device_count : 0;
}

const char* librdp_settings_usb_device_selector(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->usb_device_count)
        return NULL;
    return settings->usb_devices[index];
}

uint32_t librdp_settings_pnp_device_count(const librdp_settings* settings)
{
    return settings ? settings->pnp_device_count : 0;
}

const char* librdp_settings_pnp_device_hardware_id(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->pnp_device_count)
        return NULL;
    return settings->pnp_devices[index].hardware_id;
}

const char* librdp_settings_pnp_device_compatibility_id(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->pnp_device_count)
        return NULL;
    return settings->pnp_devices[index].compatibility_id;
}

const char* librdp_settings_pnp_device_description(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->pnp_device_count)
        return NULL;
    return settings->pnp_devices[index].description;
}

uint32_t librdp_settings_pnp_device_caps(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->pnp_device_count)
        return 0;
    return settings->pnp_devices[index].device_caps;
}

const char* librdp_settings_webauthn_provider(const librdp_settings* settings)
{
    return settings ? settings->webauthn_provider : NULL;
}

uint32_t librdp_settings_rail_app_count(const librdp_settings* settings)
{
    return settings ? settings->rail_app_count : 0;
}

const char* librdp_settings_rail_app(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->rail_app_count)
        return NULL;
    return settings->rail_apps[index];
}

const char* librdp_settings_echo_payload(const librdp_settings* settings)
{
    return settings ? settings->echo_payload : NULL;
}

const char* librdp_settings_target(const librdp_settings* settings)
{
    return settings ? settings->target : NULL;
}

const char* librdp_settings_username(const librdp_settings* settings)
{
    return settings ? settings->username : NULL;
}

const char* librdp_settings_domain(const librdp_settings* settings)
{
    return settings ? settings->domain : NULL;
}

uint16_t librdp_settings_port(const librdp_settings* settings)
{
    return settings ? settings->port : 0;
}

uint32_t librdp_settings_width(const librdp_settings* settings)
{
    return settings ? settings->width : 0;
}

uint32_t librdp_settings_height(const librdp_settings* settings)
{
    return settings ? settings->height : 0;
}

librdp_security_mode librdp_settings_security_mode(const librdp_settings* settings)
{
    return settings ? settings->security_mode : LIBRDP_SECURITY_AUTO;
}

const char* rdp_settings_password_internal(const librdp_settings* settings)
{
    return settings ? settings->password : NULL;
}

uint32_t rdp_settings_drive_device_id_internal(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->drive_count)
        return 0;
    return 0x00010000u + index;
}

uint32_t rdp_settings_printer_device_id_internal(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->printer_count)
        return 0;
    return 0x00020000u + index;
}

uint32_t rdp_settings_smartcard_device_id_internal(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->smartcard_count)
        return 0;
    return 0x00030000u + index;
}

uint32_t rdp_settings_serial_port_device_id_internal(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->serial_port_count)
        return 0;
    return 0x00040000u + index;
}

uint32_t rdp_settings_parallel_port_device_id_internal(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->parallel_port_count)
        return 0;
    return 0x00050000u + index;
}

uint32_t rdp_settings_pnp_device_id_internal(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->pnp_device_count)
        return 0;
    return 0x00060000u + index;
}
