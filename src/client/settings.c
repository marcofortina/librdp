#include <librdp/settings.h>

#include "client/settings_internal.h"

#include <stdlib.h>
#include <string.h>

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
