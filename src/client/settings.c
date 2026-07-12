/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client settings storage and validation for public API configuration.
 * Invariants: session state transitions happen in protocol order and callbacks
 * never receive invalid surfaces or channels.
 * Ownership: settings own copied strings and backend descriptors until the
 * settings object is destroyed.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: external input is treated as untrusted until validated by
 * this module or its caller.
 */


#include <librdp/settings.h>

#include "client/settings_internal.h"

#include <openssl/crypto.h>

#include <stdlib.h>
#include <string.h>

#define RDP_SETTINGS_KNOWN_FEATURES \
    ((uint32_t)LIBRDP_FEATURE_AUDIO_OUTPUT | (uint32_t)LIBRDP_FEATURE_AUDIO_INPUT | \
     (uint32_t)LIBRDP_FEATURE_VIDEO | (uint32_t)LIBRDP_FEATURE_CAMERA | \
     (uint32_t)LIBRDP_FEATURE_SMARTCARD | (uint32_t)LIBRDP_FEATURE_USB | \
     (uint32_t)LIBRDP_FEATURE_PNP | (uint32_t)LIBRDP_FEATURE_WEBAUTHN | \
     (uint32_t)LIBRDP_FEATURE_RAIL | (uint32_t)LIBRDP_FEATURE_CR2 | \
     (uint32_t)LIBRDP_FEATURE_ECHO | (uint32_t)LIBRDP_FEATURE_TELEMETRY | \
     (uint32_t)LIBRDP_FEATURE_MULTITRANSPORT)

typedef struct rdp_settings_drive
{
    char name[8];
    char* path;
    librdp_drive_policy policy;
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
    librdp_credentials_provider credentials_provider;
    void* credentials_provider_user_data;
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
    librdp_tls_policy_mode tls_policy_mode;
    int tls_use_system_store;
    char* tls_pinned_sha256;
    librdp_tls_certificate_callback tls_certificate_callback;
    void* tls_certificate_callback_user_data;
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
    librdp_usb_policy usb_policy;
    librdp_limits limits;
    uint32_t rail_app_count;
    char* rail_apps[LIBRDP_SETTINGS_MAX_RAIL_APPS];
    uint32_t pnp_device_count;
    rdp_settings_pnp_device pnp_devices[LIBRDP_SETTINGS_MAX_PNP_DEVICES];
};

#define RDP_SETTINGS_TEXT_MAX 4096u
#define RDP_SETTINGS_DRIVE_DEFAULT_MAX_OPEN_HANDLES 64u
#define RDP_SETTINGS_DRIVE_MAX_OPEN_HANDLES 1024u
#define RDP_SETTINGS_USB_DEFAULT_TRANSFER_MS 5000u
#define RDP_SETTINGS_USB_MAX_TRANSFER_MS 60000u
#define RDP_SETTINGS_LIMIT_DYNAMIC_CHANNELS 64u
#define RDP_SETTINGS_LIMIT_DYNAMIC_MESSAGE_BYTES (64u * 1024u * 1024u)
#define RDP_SETTINGS_LIMIT_FASTPATH_FRAGMENT_BYTES (16u * 1024u * 1024u)
#define RDP_SETTINGS_LIMIT_GRAPHICS_SURFACES 64u
#define RDP_SETTINGS_LIMIT_SURFACE_DIMENSION 8192u
#define RDP_SETTINGS_LIMIT_CLIPBOARD_FORMATS 64u
#define RDP_SETTINGS_LIMIT_CLIPBOARD_FILES 64u
#define RDP_SETTINGS_LIMIT_CLIPBOARD_FILE_RANGE_BYTES (4u * 1024u * 1024u)
#define RDP_SETTINGS_LIMIT_REDIRECTED_FILES 256u
#define RDP_SETTINGS_LIMIT_FILE_IO_BYTES (4u * 1024u * 1024u)
#define RDP_SETTINGS_LIMIT_DEVICE_IO_BYTES 65536u
#define RDP_SETTINGS_LIMIT_PENDING_REQUESTS 64u

static rdp_settings_secure_string_observer g_secure_string_observer;
static void* g_secure_string_observer_user_data;

void rdp_settings_secure_string_observer_for_tests(rdp_settings_secure_string_observer observer,
                                                   void* user_data)
{
    g_secure_string_observer = observer;
    g_secure_string_observer_user_data = user_data;
}

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

static char* rdp_secure_string_dup(const char* value)
{
    size_t length = 0;
    char* out = NULL;

    if (!value)
        return NULL;
    length = strlen(value) + 1u;
    out = (char*)malloc(length);
    if (!out)
        return NULL;
    memcpy(out, value, length);
    return out;
}

static void rdp_secure_string_free(char* value)
{
    size_t length = 0;

    if (!value)
        return;
    length = strlen(value) + 1u;
    OPENSSL_cleanse(value, length);
    if (g_secure_string_observer)
        g_secure_string_observer(value, length, g_secure_string_observer_user_data);
    free(value);
}

static librdp_status rdp_set_secure_string(char** field, const char* value)
{
    char* copy = NULL;

    if (!field)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (value)
    {
        copy = rdp_secure_string_dup(value);
        if (!copy)
            return LIBRDP_STATUS_NO_MEMORY;
    }
    rdp_secure_string_free(*field);
    *field = copy;
    return LIBRDP_STATUS_OK;
}

static void rdp_secure_string_free_plain(char* value)
{
    if (!value)
        return;
    OPENSSL_cleanse(value, strlen(value) + 1u);
    free(value);
}

static librdp_status rdp_credentials_copy_values(const char* username,
                                                 const char* password,
                                                 const char* domain,
                                                 char** username_out,
                                                 char** password_out,
                                                 char** domain_out)
{
    char* username_copy = NULL;
    char* password_copy = NULL;
    char* domain_copy = NULL;

    if (!username_out || !password_out || !domain_out)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (username)
    {
        username_copy = rdp_strdup(username);
        if (!username_copy)
            goto no_memory;
    }
    if (password)
    {
        password_copy = rdp_secure_string_dup(password);
        if (!password_copy)
            goto no_memory;
    }
    if (domain)
    {
        domain_copy = rdp_strdup(domain);
        if (!domain_copy)
            goto no_memory;
    }
    *username_out = username_copy;
    *password_out = password_copy;
    *domain_out = domain_copy;
    return LIBRDP_STATUS_OK;

no_memory:
    free(username_copy);
    rdp_secure_string_free_plain(password_copy);
    free(domain_copy);
    return LIBRDP_STATUS_NO_MEMORY;
}

static int rdp_credentials_valid(const librdp_credentials* credentials)
{
    return credentials && credentials->version == LIBRDP_CREDENTIALS_VERSION &&
           credentials->size >= sizeof(librdp_credentials);
}

librdp_status librdp_credentials_init(librdp_credentials* credentials)
{
    if (!credentials)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(credentials, 0, sizeof(*credentials));
    credentials->version = LIBRDP_CREDENTIALS_VERSION;
    credentials->size = (uint32_t)sizeof(*credentials);
    return LIBRDP_STATUS_OK;
}

void librdp_credentials_clear(librdp_credentials* credentials)
{
    if (!credentials)
        return;
    free(credentials->username);
    rdp_secure_string_free(credentials->password);
    free(credentials->domain);
    memset(credentials, 0, sizeof(*credentials));
    credentials->version = LIBRDP_CREDENTIALS_VERSION;
    credentials->size = (uint32_t)sizeof(*credentials);
}

librdp_status librdp_credentials_set(librdp_credentials* credentials,
                                     const char* username,
                                     const char* password,
                                     const char* domain)
{
    char* username_copy = NULL;
    char* password_copy = NULL;
    char* domain_copy = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!rdp_credentials_valid(credentials))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_credentials_copy_values(username,
                                         password,
                                         domain,
                                         &username_copy,
                                         &password_copy,
                                         &domain_copy);
    if (status != LIBRDP_STATUS_OK)
        return status;
    free(credentials->username);
    rdp_secure_string_free(credentials->password);
    free(credentials->domain);
    credentials->username = username_copy;
    credentials->password = password_copy;
    credentials->domain = domain_copy;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_drive_policy_init(librdp_drive_policy* policy)
{
    if (!policy)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(policy, 0, sizeof(*policy));
    policy->version = LIBRDP_DRIVE_POLICY_VERSION;
    policy->size = (uint32_t)sizeof(*policy);
    policy->read_only = 1;
    policy->deny_device_files = 1;
    policy->deny_symlink_escape = 1;
    policy->deny_dotfiles = 1;
    policy->max_open_handles = RDP_SETTINGS_DRIVE_DEFAULT_MAX_OPEN_HANDLES;
    return LIBRDP_STATUS_OK;
}

void librdp_usb_policy_init(librdp_usb_policy* policy)
{
    if (!policy)
        return;
    memset(policy, 0, sizeof(*policy));
    policy->version = LIBRDP_USB_POLICY_VERSION;
    policy->size = (uint32_t)sizeof(*policy);
    policy->require_explicit_consent = 1;
    policy->allow_hid = 0;
    policy->allow_mass_storage = 0;
    policy->max_transfer_ms = RDP_SETTINGS_USB_DEFAULT_TRANSFER_MS;
}

librdp_status librdp_limits_init(librdp_limits* limits)
{
    if (!limits)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(limits, 0, sizeof(*limits));
    limits->version = LIBRDP_LIMITS_VERSION;
    limits->size = (uint32_t)sizeof(*limits);
    limits->pdu_buffer_bytes = RDP_SETTINGS_LIMIT_DYNAMIC_MESSAGE_BYTES;
    limits->channel_buffer_bytes = RDP_SETTINGS_LIMIT_DYNAMIC_MESSAGE_BYTES;
    limits->dynamic_channel_count = RDP_SETTINGS_LIMIT_DYNAMIC_CHANNELS;
    limits->dynamic_channel_message_bytes = RDP_SETTINGS_LIMIT_DYNAMIC_MESSAGE_BYTES;
    limits->clipboard_formats = RDP_SETTINGS_LIMIT_CLIPBOARD_FORMATS;
    limits->clipboard_files = RDP_SETTINGS_LIMIT_CLIPBOARD_FILES;
    limits->clipboard_file_range_bytes = RDP_SETTINGS_LIMIT_CLIPBOARD_FILE_RANGE_BYTES;
    limits->file_handles = RDP_SETTINGS_LIMIT_REDIRECTED_FILES;
    limits->file_io_bytes = RDP_SETTINGS_LIMIT_FILE_IO_BYTES;
    limits->device_io_bytes = RDP_SETTINGS_LIMIT_DEVICE_IO_BYTES;
    limits->surface_count = RDP_SETTINGS_LIMIT_GRAPHICS_SURFACES;
    limits->surface_max_dimension = RDP_SETTINGS_LIMIT_SURFACE_DIMENSION;
    limits->frame_bytes = RDP_SETTINGS_LIMIT_FASTPATH_FRAGMENT_BYTES;
    limits->pending_requests = RDP_SETTINGS_LIMIT_PENDING_REQUESTS;
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

static int rdp_settings_drive_policy_valid(const librdp_drive_policy* policy)
{
    if (!policy || policy->version != LIBRDP_DRIVE_POLICY_VERSION || policy->size < sizeof(*policy))
        return 0;
    if (policy->max_open_handles > RDP_SETTINGS_DRIVE_MAX_OPEN_HANDLES)
        return 0;
    return 1;
}

static int rdp_settings_usb_policy_valid(const librdp_usb_policy* policy)
{
    if (!policy || policy->version != LIBRDP_USB_POLICY_VERSION || policy->size < sizeof(*policy))
        return 0;
    if (policy->max_transfer_ms > RDP_SETTINGS_USB_MAX_TRANSFER_MS)
        return 0;
    return 1;
}

/*
 * Validate caller-provided runtime limits against the storage compiled into
 * the current library. Limits may restrict existing arrays and buffers, but
 * cannot expand them or disable a category by setting it to zero.
 */
static int rdp_settings_limits_valid(const librdp_limits* limits)
{
    if (!limits || limits->version != LIBRDP_LIMITS_VERSION || limits->size < sizeof(*limits))
        return 0;
    if (limits->pdu_buffer_bytes == 0 ||
        limits->pdu_buffer_bytes > RDP_SETTINGS_LIMIT_DYNAMIC_MESSAGE_BYTES)
        return 0;
    if (limits->channel_buffer_bytes == 0 ||
        limits->channel_buffer_bytes > RDP_SETTINGS_LIMIT_DYNAMIC_MESSAGE_BYTES)
        return 0;
    if (limits->dynamic_channel_count == 0 ||
        limits->dynamic_channel_count > RDP_SETTINGS_LIMIT_DYNAMIC_CHANNELS)
        return 0;
    if (limits->dynamic_channel_message_bytes == 0 ||
        limits->dynamic_channel_message_bytes > RDP_SETTINGS_LIMIT_DYNAMIC_MESSAGE_BYTES)
        return 0;
    if (limits->clipboard_formats == 0 ||
        limits->clipboard_formats > RDP_SETTINGS_LIMIT_CLIPBOARD_FORMATS)
        return 0;
    if (limits->clipboard_files == 0 ||
        limits->clipboard_files > RDP_SETTINGS_LIMIT_CLIPBOARD_FILES)
        return 0;
    if (limits->clipboard_file_range_bytes == 0 ||
        limits->clipboard_file_range_bytes > RDP_SETTINGS_LIMIT_CLIPBOARD_FILE_RANGE_BYTES)
        return 0;
    if (limits->file_handles == 0 ||
        limits->file_handles > RDP_SETTINGS_LIMIT_REDIRECTED_FILES)
        return 0;
    if (limits->file_io_bytes == 0 ||
        limits->file_io_bytes > RDP_SETTINGS_LIMIT_FILE_IO_BYTES)
        return 0;
    if (limits->device_io_bytes == 0 ||
        limits->device_io_bytes > RDP_SETTINGS_LIMIT_DEVICE_IO_BYTES)
        return 0;
    if (limits->surface_count == 0 ||
        limits->surface_count > RDP_SETTINGS_LIMIT_GRAPHICS_SURFACES)
        return 0;
    if (limits->surface_max_dimension == 0 ||
        limits->surface_max_dimension > RDP_SETTINGS_LIMIT_SURFACE_DIMENSION)
        return 0;
    if (limits->frame_bytes == 0 ||
        limits->frame_bytes > RDP_SETTINGS_LIMIT_FASTPATH_FRAGMENT_BYTES)
        return 0;
    return limits->pending_requests != 0 &&
           limits->pending_requests <= RDP_SETTINGS_LIMIT_PENDING_REQUESTS;
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

static int rdp_settings_hex_value(unsigned char value)
{
    if (value >= (unsigned char)'0' && value <= (unsigned char)'9')
        return (int)(value - (unsigned char)'0');
    if (value >= (unsigned char)'a' && value <= (unsigned char)'f')
        return (int)(value - (unsigned char)'a') + 10;
    if (value >= (unsigned char)'A' && value <= (unsigned char)'F')
        return (int)(value - (unsigned char)'A') + 10;
    return -1;
}

static int rdp_settings_normalize_sha256_fingerprint(const char* value,
                                                     char output[LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH + 1u])
{
    size_t written = 0;

    if (!value || !output)
        return 0;
    for (; *value; value++)
    {
        int hex = rdp_settings_hex_value((unsigned char)*value);

        if (*value == ':' || *value == '-' || *value == ' ')
            continue;
        if (hex < 0 || written >= LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH)
            return 0;
        output[written++] = (char)((hex < 10) ? ('0' + hex) : ('a' + (hex - 10)));
    }
    if (written != LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH)
        return 0;
    output[written] = '\0';
    return 1;
}

static int rdp_settings_valid_webauthn_provider(const char* value)
{
    if (!value)
        return 1;
    if (strcmp(value, "mock") == 0)
        return 1;
    if (strcmp(value, "fido2") == 0)
        return 1;
    return ((strncmp(value, "mock=", 5u) == 0 && value[5] != '\0') ||
            (strncmp(value, "fido2=", 6u) == 0 && value[6] != '\0')) &&
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

static int rdp_settings_valid_feature_mask(librdp_feature feature)
{
    uint32_t value = (uint32_t)feature;

    return value != 0 && (value & ~RDP_SETTINGS_KNOWN_FEATURES) == 0;
}

static int rdp_settings_valid_single_feature(librdp_feature feature)
{
    uint32_t value = (uint32_t)feature;

    return rdp_settings_valid_feature_mask(feature) && (value & (value - 1u)) == 0;
}

/*
 * Backend readiness is deliberately stricter than the feature bit. It models
 * whether an application supplied the host-side object needed to make the
 * negotiated protocol useful, not merely whether the protocol parser exists.
 */
static int rdp_settings_feature_backend_ready(const librdp_settings* settings, librdp_feature feature)
{
    const char* provider = NULL;

    if (!settings)
        return 0;

    switch (feature)
    {
        case LIBRDP_FEATURE_AUDIO_OUTPUT:
            return settings->audio_output_device != NULL;
        case LIBRDP_FEATURE_AUDIO_INPUT:
            return settings->audio_input_device != NULL;
        case LIBRDP_FEATURE_VIDEO:
            return settings->video_output_path != NULL;
        case LIBRDP_FEATURE_CAMERA:
            return settings->camera_count > 0;
        case LIBRDP_FEATURE_SMARTCARD:
#if defined(RDP_HAVE_PCSC) || defined(RDP_HAVE_WINPR_SMARTCARD)
            return settings->smartcard_count > 0;
#else
            return 0;
#endif
        case LIBRDP_FEATURE_USB:
#ifdef RDP_HAVE_LIBUSB
            return settings->usb_device_count > 0;
#else
            return 0;
#endif
        case LIBRDP_FEATURE_PNP:
            return settings->pnp_device_count > 0;
        case LIBRDP_FEATURE_WEBAUTHN:
            provider = settings->webauthn_provider;
            if (!provider || strcmp(provider, "mock") == 0 || strncmp(provider, "mock=", 5u) == 0)
                return 1;
            if (strcmp(provider, "fido2") == 0 || strncmp(provider, "fido2=", 6u) == 0)
            {
#ifdef RDP_HAVE_FIDO2
                return 1;
#else
                return 0;
#endif
            }
            return 0;
        case LIBRDP_FEATURE_RAIL:
            return settings->rail_app_count > 0;
        case LIBRDP_FEATURE_CR2:
        case LIBRDP_FEATURE_TELEMETRY:
        case LIBRDP_FEATURE_MULTITRANSPORT:
            return 1;
        case LIBRDP_FEATURE_ECHO:
            return settings->echo_payload != NULL;
        default:
            return 0;
    }
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
    settings->tls_policy_mode = LIBRDP_TLS_POLICY_STRICT;
    settings->tls_use_system_store = 1;
    librdp_usb_policy_init(&settings->usb_policy);
    if (librdp_limits_init(&settings->limits) != LIBRDP_STATUS_OK)
    {
        free(settings);
        return NULL;
    }
    return settings;
}

/*
 * Clone every settings field through the public setters so validation and
 * ownership rules match application-created settings. On any failed copy the
 * partially built clone is destroyed before returning NULL.
 */
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
    copy->credentials_provider = settings->credentials_provider;
    copy->credentials_provider_user_data = settings->credentials_provider_user_data;
    copy->tls_policy_mode = settings->tls_policy_mode;
    copy->tls_use_system_store = settings->tls_use_system_store;
    copy->tls_certificate_callback = settings->tls_certificate_callback;
    copy->tls_certificate_callback_user_data = settings->tls_certificate_callback_user_data;
    copy->usb_policy = settings->usb_policy;
    copy->limits = settings->limits;

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
        (settings->tls_pinned_sha256 &&
         rdp_set_string(&copy->tls_pinned_sha256, settings->tls_pinned_sha256) != LIBRDP_STATUS_OK) ||
        (settings->echo_payload &&
         librdp_settings_set_echo_payload(copy, settings->echo_payload) != LIBRDP_STATUS_OK))
    {
        librdp_settings_free(copy);
        return NULL;
    }
    for (uint32_t i = 0; i < settings->drive_count; i++)
    {
        if (librdp_settings_add_drive(copy, settings->drives[i].name, settings->drives[i].path) !=
            LIBRDP_STATUS_OK ||
            librdp_settings_set_drive_policy(copy, i, &settings->drives[i].policy) != LIBRDP_STATUS_OK)
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
    rdp_secure_string_free(settings->password);
    free(settings->domain);
    free(settings->audio_output_device);
    free(settings->audio_input_device);
    free(settings->video_output_path);
    free(settings->webauthn_provider);
    free(settings->echo_payload);
    free(settings->tls_pinned_sha256);
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
    return rdp_set_secure_string(&settings->password, password);
}

librdp_status librdp_settings_set_domain(librdp_settings* settings, const char* domain)
{
    if (!settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_set_string(&settings->domain, domain);
}

librdp_status librdp_settings_set_credentials(librdp_settings* settings,
                                              const librdp_credentials* credentials)
{
    char* username_copy = NULL;
    char* password_copy = NULL;
    char* domain_copy = NULL;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!credentials)
    {
        free(settings->username);
        settings->username = NULL;
        rdp_secure_string_free(settings->password);
        settings->password = NULL;
        free(settings->domain);
        settings->domain = NULL;
        return LIBRDP_STATUS_OK;
    }
    if (!rdp_credentials_valid(credentials))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_credentials_copy_values(credentials->username,
                                         credentials->password,
                                         credentials->domain,
                                         &username_copy,
                                         &password_copy,
                                         &domain_copy);
    if (status != LIBRDP_STATUS_OK)
        return status;
    free(settings->username);
    rdp_secure_string_free(settings->password);
    free(settings->domain);
    settings->username = username_copy;
    settings->password = password_copy;
    settings->domain = domain_copy;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_settings_set_credentials_provider(librdp_settings* settings,
                                                       librdp_credentials_provider provider,
                                                       void* user_data)
{
    if (!settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    settings->credentials_provider = provider;
    settings->credentials_provider_user_data = user_data;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_settings_set_limits(librdp_settings* settings, const librdp_limits* limits)
{
    librdp_limits defaults;

    if (!settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!limits)
    {
        if (librdp_limits_init(&defaults) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        limits = &defaults;
    }
    if (!rdp_settings_limits_valid(limits))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (settings->width > limits->surface_max_dimension ||
        settings->height > limits->surface_max_dimension)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    settings->limits = *limits;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_settings_get_limits(const librdp_settings* settings, librdp_limits* limits)
{
    if (!settings || !limits)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *limits = settings->limits;
    return LIBRDP_STATUS_OK;
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
    if (width > settings->limits.surface_max_dimension || height > settings->limits.surface_max_dimension)
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
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

librdp_status librdp_tls_policy_init(librdp_tls_policy* policy)
{
    if (!policy)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(policy, 0, sizeof(*policy));
    policy->version = LIBRDP_TLS_POLICY_VERSION;
    policy->size = (uint32_t)sizeof(*policy);
    policy->mode = LIBRDP_TLS_POLICY_STRICT;
    policy->use_system_store = 1;
    return LIBRDP_STATUS_OK;
}

/*
 * Copy TLS policy into settings with all externally supplied fingerprint text
 * normalized once. TOFU is callback-controlled because the core has no hidden
 * persistent store and must not invent host-specific trust state.
 */
librdp_status librdp_settings_set_tls_policy(librdp_settings* settings, const librdp_tls_policy* policy)
{
    librdp_tls_policy defaults;
    char normalized[LIBRDP_TLS_SHA256_FINGERPRINT_HEX_LENGTH + 1u];
    char* pinned_copy = NULL;

    if (!settings)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!policy)
    {
        if (librdp_tls_policy_init(&defaults) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        policy = &defaults;
    }
    if (policy->version != LIBRDP_TLS_POLICY_VERSION || policy->size < sizeof(*policy) ||
        policy->mode < LIBRDP_TLS_POLICY_STRICT || policy->mode > LIBRDP_TLS_POLICY_INSECURE_LAB)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (policy->mode == LIBRDP_TLS_POLICY_PINNED_FINGERPRINT)
    {
        if (!rdp_settings_normalize_sha256_fingerprint(policy->pinned_sha256, normalized))
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        pinned_copy = rdp_strdup(normalized);
        if (!pinned_copy)
            return LIBRDP_STATUS_NO_MEMORY;
    }
    else if (policy->pinned_sha256)
    {
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    if (policy->mode == LIBRDP_TLS_POLICY_TOFU && !policy->certificate_callback)
    {
        free(pinned_copy);
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    }

    free(settings->tls_pinned_sha256);
    settings->tls_pinned_sha256 = pinned_copy;
    settings->tls_policy_mode = policy->mode;
    settings->tls_use_system_store = policy->use_system_store ? 1 : 0;
    settings->tls_certificate_callback = policy->certificate_callback;
    settings->tls_certificate_callback_user_data = policy->certificate_callback_user_data;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_settings_get_tls_policy(const librdp_settings* settings, librdp_tls_policy* policy)
{
    if (!settings || !policy)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (librdp_tls_policy_init(policy) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    policy->mode = settings->tls_policy_mode;
    policy->use_system_store = settings->tls_use_system_store;
    policy->pinned_sha256 = settings->tls_pinned_sha256;
    policy->certificate_callback = settings->tls_certificate_callback;
    policy->certificate_callback_user_data = settings->tls_certificate_callback_user_data;
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
    (void)librdp_drive_policy_init(&drive->policy);
    settings->drive_count++;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_settings_set_drive_policy(librdp_settings* settings,
                                               uint32_t index,
                                               const librdp_drive_policy* policy)
{
    if (!settings || index >= settings->drive_count || !rdp_settings_drive_policy_valid(policy))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    settings->drives[index].policy = *policy;
    if (settings->drives[index].policy.max_open_handles == 0)
        settings->drives[index].policy.max_open_handles = RDP_SETTINGS_DRIVE_DEFAULT_MAX_OPEN_HANDLES;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_settings_get_drive_policy(const librdp_settings* settings,
                                               uint32_t index,
                                               librdp_drive_policy* policy)
{
    if (!settings || index >= settings->drive_count || !policy)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *policy = settings->drives[index].policy;
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
    if (!settings || !rdp_settings_valid_feature_mask(feature))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (enabled)
        settings->features |= (uint32_t)feature;
    else
        settings->features &= ~((uint32_t)feature);
    return LIBRDP_STATUS_OK;
}

int librdp_settings_feature_enabled(const librdp_settings* settings, librdp_feature feature)
{
    if (!settings || !rdp_settings_valid_feature_mask(feature))
        return 0;
    return (settings->features & (uint32_t)feature) != 0;
}

librdp_status librdp_settings_get_feature_status(const librdp_settings* settings,
                                                 librdp_feature feature,
                                                 librdp_feature_status* status)
{
    if (!settings || !status || !rdp_settings_valid_single_feature(feature))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(status, 0, sizeof(*status));
    status->feature = feature;
    status->requested = librdp_settings_feature_enabled(settings, feature) ? 1 : 0;
    status->built = 1;
    if (!status->requested)
    {
        status->reason = LIBRDP_FEATURE_REASON_NOT_REQUESTED;
        return LIBRDP_STATUS_OK;
    }
    status->backend_ready = rdp_settings_feature_backend_ready(settings, feature) ? 1 : 0;
    if (!status->backend_ready)
        status->reason = LIBRDP_FEATURE_REASON_BACKEND_UNAVAILABLE;
    else
        status->reason = LIBRDP_FEATURE_REASON_NONE;
    return LIBRDP_STATUS_OK;
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

librdp_status librdp_settings_set_usb_policy(librdp_settings* settings,
                                             const librdp_usb_policy* policy)
{
    if (!settings || !rdp_settings_usb_policy_valid(policy))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    settings->usb_policy = *policy;
    if (settings->usb_policy.max_transfer_ms == 0)
        settings->usb_policy.max_transfer_ms = RDP_SETTINGS_USB_DEFAULT_TRANSFER_MS;
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_settings_get_usb_policy(const librdp_settings* settings,
                                             librdp_usb_policy* policy)
{
    if (!settings || !policy)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *policy = settings->usb_policy;
    return LIBRDP_STATUS_OK;
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

librdp_credentials_provider rdp_settings_credentials_provider_internal(const librdp_settings* settings,
                                                                       void** user_data)
{
    if (user_data)
        *user_data = settings ? settings->credentials_provider_user_data : NULL;
    return settings ? settings->credentials_provider : NULL;
}

uint32_t rdp_settings_drive_device_id_internal(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->drive_count)
        return 0;
    return 0x00010000u + index;
}

const librdp_drive_policy* rdp_settings_drive_policy_internal(const librdp_settings* settings, uint32_t index)
{
    if (!settings || index >= settings->drive_count)
        return NULL;
    return &settings->drives[index].policy;
}

const librdp_usb_policy* rdp_settings_usb_policy_internal(const librdp_settings* settings)
{
    return settings ? &settings->usb_policy : NULL;
}

const librdp_limits* rdp_settings_limits_internal(const librdp_settings* settings)
{
    return settings ? &settings->limits : NULL;
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
