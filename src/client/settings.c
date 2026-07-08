#include <librdp/settings.h>

#include "client/settings_internal.h"

#include <stdlib.h>
#include <string.h>

typedef struct rdp_settings_drive
{
    char name[8];
    char* path;
} rdp_settings_drive;

struct librdp_settings
{
    char* target;
    char* username;
    char* password;
    char* domain;
    uint16_t port;
    uint32_t width;
    uint32_t height;
    librdp_security_mode security_mode;
    uint32_t drive_count;
    rdp_settings_drive drives[LIBRDP_SETTINGS_MAX_DRIVES];
};

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
    copy->security_mode = settings->security_mode;

    if ((settings->target && librdp_settings_set_target(copy, settings->target) != LIBRDP_STATUS_OK) ||
        (settings->username && librdp_settings_set_username(copy, settings->username) != LIBRDP_STATUS_OK) ||
        (settings->password && librdp_settings_set_password(copy, settings->password) != LIBRDP_STATUS_OK) ||
        (settings->domain && librdp_settings_set_domain(copy, settings->domain) != LIBRDP_STATUS_OK))
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
    for (uint32_t i = 0; i < settings->drive_count; i++)
        free(settings->drives[i].path);
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
