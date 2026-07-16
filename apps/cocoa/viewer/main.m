/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: native Cocoa viewer for exercising public client APIs.
 * Invariants: AppKit owns windowing on the main thread, librdp session dispatch
 * is serialized on the same thread, and framebuffer bytes are borrowed only
 * while drawing.
 * Ownership: settings are released after session creation, the session owns
 * protocol state, and AppKit owns windows, views, timers, and events.
 * Threading: single-threaded AppKit event loop; callbacks are invoked by the
 * timer-driven session dispatch path.
 * Trust boundary: command-line values and remote desktop pixels are untrusted
 * inputs; credentials are copied into settings and never printed.
 */

#import <Cocoa/Cocoa.h>
#include <librdp/librdp.h>

#include "cocoa_media.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct cocoa_viewer_options
{
    const char* target;
    const char* username;
    const char* password;
    const char* domain;
    const char* rail_app;
    const char* gateway_url;
    const char* gateway_username;
    const char* gateway_password;
    const char* gateway_domain;
    const char* audio_output_device;
    const char* audio_input_device;
    const char* video_output_path;
    const char* camera_source;
    int argc;
    char** argv;
    uint16_t port;
    uint32_t width;
    uint32_t height;
    librdp_security_mode security;
    librdp_gateway_mode gateway_mode;
    uint32_t gateway_timeout_ms;
    int gateway_has_timeout;
    int gateway_no_session_credentials;
    int accept_tls_certificate;
    int tls_prompt_certificate;
    int tls_accept_any_certificate;
    int audio_output_requested;
    int audio_input_requested;
    int video_requested;
    int camera_requested;
    int show_help;
} cocoa_viewer_options;

#define COCOA_AUDIO_OUTPUT_FORMATS_MAX 16u
#define COCOA_AUDIO_INPUT_BUFFER_BYTES 16384u

@class CocoaViewerController;

@interface CocoaViewerView : NSView
@property(nonatomic, assign) CocoaViewerController* controller;
@end

@interface CocoaViewerController : NSObject
{
    librdp_audio_format _audioOutputFormats[COCOA_AUDIO_OUTPUT_FORMATS_MAX];
    uint8_t _audioInputBuffer[COCOA_AUDIO_INPUT_BUFFER_BYTES];
}
@property(nonatomic, assign) librdp_session* session;
@property(nonatomic, strong) NSWindow* window;
@property(nonatomic, strong) CocoaViewerView* view;
@property(nonatomic, strong) NSTimer* timer;
@property(nonatomic, strong) NSCursor* currentCursor;
@property(nonatomic, assign) cocoa_audio_backend* audio;
@property(nonatomic, assign) cocoa_camera_source* camera;
@property(nonatomic, assign) FILE* videoOutputFile;
@property(nonatomic, assign) const char* audioOutputDevice;
@property(nonatomic, assign) const char* audioInputDevice;
@property(nonatomic, assign) const char* cameraSource;
@property(nonatomic, assign) uint32_t audioOutputFormatCount;
@property(nonatomic, assign) uint32_t audioOutputCurrentFormat;
@property(nonatomic, assign) size_t audioInputChunk;
@property(nonatomic, assign) NSInteger pasteboardChangeCount;
@property(nonatomic, assign) BOOL dirty;
@property(nonatomic, assign) BOOL closed;
@property(nonatomic, assign) BOOL audioOutputRequested;
@property(nonatomic, assign) BOOL audioInputRequested;
@property(nonatomic, assign) BOOL audioInputActive;
@property(nonatomic, assign) BOOL videoRequested;
@property(nonatomic, assign) BOOL cameraRequested;
- (id)initWithSession:(librdp_session*)session width:(uint32_t)width height:(uint32_t)height;
- (BOOL)configureMediaWithOptions:(const cocoa_viewer_options*)options;
- (void)shutdownMedia;
- (void)start;
- (void)markDirty;
- (void)driveSession:(NSTimer*)timer;
- (void)pumpAudioInput;
- (void)handleAudioEnvelope:(librdp_session*)session envelope:(const librdp_event_envelope*)envelope;
- (void)handleVideoEnvelope:(librdp_session*)session envelope:(const librdp_event_envelope*)envelope;
- (void)handleChannelEnvelope:(librdp_session*)session envelope:(const librdp_event_envelope*)envelope;
- (void)sendResizeForView;
- (void)sendMouseEvent:(NSEvent*)event button:(librdp_mouse_button)button state:(librdp_mouse_state)state;
- (void)sendWheelEvent:(NSEvent*)event;
- (void)sendKeyEvent:(NSEvent*)event pressed:(BOOL)pressed;
- (void)applyPointerEvent:(const librdp_pointer_event*)pointer;
- (void)handleClipboardEnvelope:(const librdp_event_envelope*)envelope;
- (void)publishLocalPasteboardIfChanged;
@end

static void cocoa_viewer_usage(FILE* stream, const char* program)
{
    fprintf(stream,
            "usage: %s --target host [--port port] [--user name] [--password value] "
            "[--domain name] [--width px] [--height px] [--security auto|rdp|tls|nla] "
            "[--tls-prompt-cert] [--tls-accept-any-cert] [--accept-tls-certificate] "
            "[--gateway url] [--gateway-mode http-connect|rdg-http] "
            "[--gateway-user name] [--gateway-password value] [--gateway-domain name] "
            "[--gateway-timeout ms] [--gateway-no-session-credentials] [--drive name=path] "
            "[--serial name=path] [--parallel name=path] [--printer name=driver=path] "
            "[--audio-output [device=name]] [--audio-input [device=name]] [--video file=path] "
            "[--camera device=default|device=id|file=path] [--smartcard [pcsc|source]] [--usb vid:pid|bus:dev] "
            "[--pnp] [--webauthn [fido2|mock|provider]] [--webauthn-rp-id id] "
            "[--rail app=path] [--cr2] [--echo] [--telemetry] [--multitransport]\n",
            program);
}

static int cocoa_viewer_need_value(int argc, int* index, const char* option)
{
    if (*index + 1 < argc)
    {
        *index += 1;
        return 1;
    }
    fprintf(stderr, "%s requires a value\n", option);
    return 0;
}

static int cocoa_viewer_parse_u16(const char* text, uint16_t* value)
{
    char* end = NULL;
    unsigned long parsed = 0;

    if (!text || !value)
        return 0;
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed == 0 || parsed > UINT16_MAX)
        return 0;
    *value = (uint16_t)parsed;
    return 1;
}

static int cocoa_viewer_parse_size(const char* text, uint32_t* value)
{
    char* end = NULL;
    unsigned long parsed = 0;

    if (!text || !value)
        return 0;
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed == 0 || parsed > 8192ul)
        return 0;
    *value = (uint32_t)parsed;
    return 1;
}

static int cocoa_viewer_parse_u32(const char* text, uint32_t* value)
{
    char* end = NULL;
    unsigned long parsed = 0;

    if (!text || !value)
        return 0;
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed > UINT32_MAX)
        return 0;
    *value = (uint32_t)parsed;
    return 1;
}

static int cocoa_viewer_parse_security(const char* text, librdp_security_mode* mode)
{
    if (!text || !mode)
        return 0;
    if (strcmp(text, "auto") == 0)
        *mode = LIBRDP_SECURITY_AUTO;
    else if (strcmp(text, "rdp") == 0)
        *mode = LIBRDP_SECURITY_STANDARD;
    else if (strcmp(text, "tls") == 0)
        *mode = LIBRDP_SECURITY_TLS;
    else if (strcmp(text, "nla") == 0)
        *mode = LIBRDP_SECURITY_NLA;
    else
        return 0;
    return 1;
}

static int cocoa_viewer_parse_gateway_mode(const char* text, librdp_gateway_mode* mode)
{
    if (!text || !mode)
        return 0;
    if (strcmp(text, "http-connect") == 0)
        *mode = LIBRDP_GATEWAY_HTTP_CONNECT;
    else if (strcmp(text, "rdg-http") == 0)
        *mode = LIBRDP_GATEWAY_RDG_HTTP;
    else
        return 0;
    return 1;
}

static const char* cocoa_viewer_rail_value(const char* text)
{
    const char prefix[] = "app=";

    if (!text)
        return NULL;
    if (strncmp(text, prefix, sizeof(prefix) - 1u) != 0 || text[sizeof(prefix) - 1u] == '\0')
        return NULL;
    return text + sizeof(prefix) - 1u;
}

static const char* cocoa_viewer_value_after_prefix(const char* text, const char* prefix)
{
    size_t prefix_len = 0;

    if (!text || !prefix)
        return NULL;
    prefix_len = strlen(prefix);
    if (strncmp(text, prefix, prefix_len) != 0 || text[prefix_len] == '\0')
        return NULL;
    return text + prefix_len;
}

static int cocoa_viewer_add_drive_arg(librdp_settings* settings, const char* text)
{
    const char* separator = NULL;
    char name[8];
    size_t name_len = 0;

    if (!settings || !text)
        return 0;
    separator = strchr(text, '=');
    if (!separator || separator == text || separator[1] == '\0')
        return 0;
    name_len = (size_t)(separator - text);
    if (name_len >= sizeof(name))
        return 0;
    memcpy(name, text, name_len);
    name[name_len] = '\0';
    return librdp_settings_add_drive(settings, name, separator + 1) == LIBRDP_STATUS_OK;
}

static int cocoa_viewer_add_port_arg(librdp_settings* settings, const char* text, int serial)
{
    const char* separator = NULL;
    char name[8];
    size_t name_len = 0;

    if (!settings || !text)
        return 0;
    separator = strchr(text, '=');
    if (!separator || separator == text || separator[1] == '\0')
        return 0;
    name_len = (size_t)(separator - text);
    if (name_len >= sizeof(name))
        return 0;
    memcpy(name, text, name_len);
    name[name_len] = '\0';
    if (serial)
        return librdp_settings_add_serial_port(settings, name, separator + 1) == LIBRDP_STATUS_OK;
    return librdp_settings_add_parallel_port(settings, name, separator + 1) == LIBRDP_STATUS_OK;
}

static int cocoa_viewer_add_printer_arg(librdp_settings* settings, const char* text)
{
    const char* first = NULL;
    const char* second = NULL;
    char name[128];
    char driver[128];
    size_t name_len = 0;
    size_t driver_len = 0;

    if (!settings || !text)
        return 0;
    first = strchr(text, '=');
    if (!first || first == text || first[1] == '\0')
        return 0;
    second = strchr(first + 1, '=');
    if (!second || second == first + 1 || second[1] == '\0')
        return 0;
    name_len = (size_t)(first - text);
    driver_len = (size_t)(second - first - 1u);
    if (name_len >= sizeof(name) || driver_len >= sizeof(driver))
        return 0;
    memcpy(name, text, name_len);
    name[name_len] = '\0';
    memcpy(driver, first + 1, driver_len);
    driver[driver_len] = '\0';
    return librdp_settings_add_printer(settings, name, driver, second + 1) == LIBRDP_STATUS_OK;
}

static const char* cocoa_viewer_optional_value(int argc, int* index, char** argv)
{
    if (!index || !argv || *index + 1 >= argc)
        return NULL;
    if (strncmp(argv[*index + 1], "--", 2) == 0)
        return NULL;
    *index += 1;
    return argv[*index];
}

/*
 * Parse viewer launch policy into borrowed command-line views. Credentials and
 * gateway settings are copied later by public settings setters, so this phase
 * only validates syntax and option combinations.
 */
static int cocoa_viewer_parse_args(int argc, char** argv, cocoa_viewer_options* options)
{
    int i = 0;

    if (!options)
        return 0;
    memset(options, 0, sizeof(*options));
    options->argc = argc;
    options->argv = argv;
    options->port = 3389u;
    options->width = 1024u;
    options->height = 768u;
    options->security = LIBRDP_SECURITY_AUTO;
    options->gateway_mode = LIBRDP_GATEWAY_HTTP_CONNECT;
    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
            options->show_help = 1;
        else if (strcmp(argv[i], "--target") == 0)
        {
            if (!cocoa_viewer_need_value(argc, &i, argv[i]))
                return 0;
            options->target = argv[i];
        }
        else if (strcmp(argv[i], "--port") == 0)
        {
            if (!cocoa_viewer_need_value(argc, &i, argv[i]) ||
                !cocoa_viewer_parse_u16(argv[i], &options->port))
                return 0;
        }
        else if (strcmp(argv[i], "--user") == 0)
        {
            if (!cocoa_viewer_need_value(argc, &i, argv[i]))
                return 0;
            options->username = argv[i];
        }
        else if (strcmp(argv[i], "--password") == 0)
        {
            if (!cocoa_viewer_need_value(argc, &i, argv[i]))
                return 0;
            options->password = argv[i];
        }
        else if (strcmp(argv[i], "--domain") == 0)
        {
            if (!cocoa_viewer_need_value(argc, &i, argv[i]))
                return 0;
            options->domain = argv[i];
        }
        else if (strcmp(argv[i], "--width") == 0)
        {
            if (!cocoa_viewer_need_value(argc, &i, argv[i]) ||
                !cocoa_viewer_parse_size(argv[i], &options->width))
                return 0;
        }
        else if (strcmp(argv[i], "--height") == 0)
        {
            if (!cocoa_viewer_need_value(argc, &i, argv[i]) ||
                !cocoa_viewer_parse_size(argv[i], &options->height))
                return 0;
        }
        else if (strcmp(argv[i], "--security") == 0)
        {
            if (!cocoa_viewer_need_value(argc, &i, argv[i]) ||
                !cocoa_viewer_parse_security(argv[i], &options->security))
                return 0;
        }
        else if (strcmp(argv[i], "--tls-prompt-cert") == 0)
            options->tls_prompt_certificate = 1;
        else if (strcmp(argv[i], "--tls-accept-any-cert") == 0)
            options->tls_accept_any_certificate = 1;
        else if (strcmp(argv[i], "--accept-tls-certificate") == 0)
        {
            options->accept_tls_certificate = 1;
            options->tls_accept_any_certificate = 1;
        }
        else if (strcmp(argv[i], "--rail") == 0)
        {
            if (!cocoa_viewer_need_value(argc, &i, argv[i]))
                return 0;
            options->rail_app = cocoa_viewer_rail_value(argv[i]);
            if (!options->rail_app)
                return 0;
        }
        else if (strcmp(argv[i], "--gateway") == 0)
        {
            if (!cocoa_viewer_need_value(argc, &i, argv[i]))
                return 0;
            options->gateway_url = argv[i];
        }
        else if (strcmp(argv[i], "--gateway-mode") == 0)
        {
            if (!cocoa_viewer_need_value(argc, &i, argv[i]) ||
                !cocoa_viewer_parse_gateway_mode(argv[i], &options->gateway_mode))
                return 0;
        }
        else if (strcmp(argv[i], "--gateway-user") == 0)
        {
            if (!cocoa_viewer_need_value(argc, &i, argv[i]))
                return 0;
            options->gateway_username = argv[i];
        }
        else if (strcmp(argv[i], "--gateway-password") == 0)
        {
            if (!cocoa_viewer_need_value(argc, &i, argv[i]))
                return 0;
            options->gateway_password = argv[i];
        }
        else if (strcmp(argv[i], "--gateway-domain") == 0)
        {
            if (!cocoa_viewer_need_value(argc, &i, argv[i]))
                return 0;
            options->gateway_domain = argv[i];
        }
        else if (strcmp(argv[i], "--gateway-timeout") == 0)
        {
            if (!cocoa_viewer_need_value(argc, &i, argv[i]) ||
                !cocoa_viewer_parse_u32(argv[i], &options->gateway_timeout_ms))
                return 0;
            options->gateway_has_timeout = 1;
        }
        else if (strcmp(argv[i], "--gateway-no-session-credentials") == 0)
            options->gateway_no_session_credentials = 1;
        else if (strcmp(argv[i], "--drive") == 0 ||
                 strcmp(argv[i], "--serial") == 0 ||
                 strcmp(argv[i], "--parallel") == 0 ||
                 strcmp(argv[i], "--printer") == 0 ||
                 strcmp(argv[i], "--video") == 0 ||
                 strcmp(argv[i], "--camera") == 0 ||
                 strcmp(argv[i], "--usb") == 0 ||
                 strcmp(argv[i], "--webauthn-rp-id") == 0)
        {
            if (!cocoa_viewer_need_value(argc, &i, argv[i]))
                return 0;
        }
        else if (strcmp(argv[i], "--audio-output") == 0 ||
                 strcmp(argv[i], "--audio-input") == 0 ||
                 strcmp(argv[i], "--smartcard") == 0 ||
                 strcmp(argv[i], "--webauthn") == 0)
        {
            if (i + 1 < argc && strncmp(argv[i + 1], "--", 2) != 0)
                i++;
        }
        else if (strcmp(argv[i], "--pnp") == 0 ||
                 strcmp(argv[i], "--cr2") == 0 ||
                 strcmp(argv[i], "--echo") == 0 ||
                 strcmp(argv[i], "--telemetry") == 0 ||
                 strcmp(argv[i], "--multitransport") == 0)
        {
        }
        else
        {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            return 0;
        }
    }
    if (!options->show_help && (!options->target || options->target[0] == '\0'))
    {
        fprintf(stderr, "--target is required\n");
        return 0;
    }
    return 1;
}

/*
 * Apply feature-oriented CLI arguments after the base connection settings have
 * been created. This pass crosses the local CLI trust boundary, writes directly
 * into librdp_settings, and relies on public validation for selector syntax,
 * ownership copies, feature state, and per-setting limit checks.
 */
static int cocoa_viewer_apply_feature_args(librdp_settings* settings, cocoa_viewer_options* options)
{
    int i = 1;

    if (!settings || !options)
        return 0;
    while (i < options->argc)
    {
        char** argv = options->argv;

        if (strcmp(argv[i], "--drive") == 0)
        {
            if (!cocoa_viewer_need_value(options->argc, &i, argv[i]) ||
                !cocoa_viewer_add_drive_arg(settings, argv[i]))
                return 0;
        }
        else if (strcmp(argv[i], "--serial") == 0)
        {
            if (!cocoa_viewer_need_value(options->argc, &i, argv[i]) ||
                !cocoa_viewer_add_port_arg(settings, argv[i], 1))
                return 0;
        }
        else if (strcmp(argv[i], "--parallel") == 0)
        {
            if (!cocoa_viewer_need_value(options->argc, &i, argv[i]) ||
                !cocoa_viewer_add_port_arg(settings, argv[i], 0))
                return 0;
        }
        else if (strcmp(argv[i], "--printer") == 0)
        {
            if (!cocoa_viewer_need_value(options->argc, &i, argv[i]) ||
                !cocoa_viewer_add_printer_arg(settings, argv[i]))
                return 0;
        }
        else if (strcmp(argv[i], "--audio-output") == 0)
        {
            const char* value = cocoa_viewer_optional_value(options->argc, &i, argv);
            const char* device = cocoa_viewer_value_after_prefix(value, "device=");

            if (!device)
                device = value ? value : "coreaudio";
            options->audio_output_requested = 1;
            options->audio_output_device = device;
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_OUTPUT, 1) != LIBRDP_STATUS_OK ||
                librdp_settings_set_audio_output_device(settings, device) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--audio-input") == 0)
        {
            const char* value = cocoa_viewer_optional_value(options->argc, &i, argv);
            const char* device = cocoa_viewer_value_after_prefix(value, "device=");

            if (!device)
                device = value ? value : "coreaudio";
            options->audio_input_requested = 1;
            options->audio_input_device = device;
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_AUDIO_INPUT, 1) != LIBRDP_STATUS_OK ||
                librdp_settings_set_audio_input_device(settings, device) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--video") == 0)
        {
            const char* value = NULL;
            const char* path = NULL;

            if (!cocoa_viewer_need_value(options->argc, &i, argv[i]))
                return 0;
            value = argv[i];
            path = cocoa_viewer_value_after_prefix(value, "file=");
            if (!path)
                path = value;
            options->video_requested = 1;
            options->video_output_path = path;
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_VIDEO, 1) != LIBRDP_STATUS_OK ||
                librdp_settings_set_video_output_path(settings, path) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--camera") == 0)
        {
            if (!cocoa_viewer_need_value(options->argc, &i, argv[i]) ||
                !cocoa_camera_source_allowed(argv[i]) ||
                librdp_settings_enable_feature(settings, LIBRDP_FEATURE_CAMERA, 1) != LIBRDP_STATUS_OK ||
                librdp_settings_add_camera(settings, argv[i]) != LIBRDP_STATUS_OK)
                return 0;
            options->camera_requested = 1;
            options->camera_source = argv[i];
        }
        else if (strcmp(argv[i], "--smartcard") == 0)
        {
            const char* value = cocoa_viewer_optional_value(options->argc, &i, argv);

            if (!value)
                value = "pcsc";
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_SMARTCARD, 1) != LIBRDP_STATUS_OK ||
                librdp_settings_add_smartcard(settings, value) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--usb") == 0)
        {
            if (!cocoa_viewer_need_value(options->argc, &i, argv[i]) ||
                librdp_settings_enable_feature(settings, LIBRDP_FEATURE_USB, 1) != LIBRDP_STATUS_OK ||
                librdp_settings_add_usb_device(settings, argv[i]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--pnp") == 0)
        {
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_PNP, 1) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--webauthn") == 0)
        {
            const char* value = cocoa_viewer_optional_value(options->argc, &i, argv);

            if (!value)
                value = "fido2";
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_WEBAUTHN, 1) != LIBRDP_STATUS_OK ||
                librdp_settings_set_webauthn_provider(settings, value) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--webauthn-rp-id") == 0)
        {
            if (!cocoa_viewer_need_value(options->argc, &i, argv[i]) ||
                librdp_settings_add_webauthn_rp_id(settings, argv[i]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--cr2") == 0)
        {
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_CR2, 1) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--echo") == 0)
        {
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_ECHO, 1) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--telemetry") == 0)
        {
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_TELEMETRY, 1) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--multitransport") == 0)
        {
            if (librdp_settings_enable_feature(settings, LIBRDP_FEATURE_MULTITRANSPORT, 1) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--tls-prompt-cert") == 0 ||
                 strcmp(argv[i], "--tls-accept-any-cert") == 0 ||
                 strcmp(argv[i], "--accept-tls-certificate") == 0 ||
                 strcmp(argv[i], "--gateway-no-session-credentials") == 0)
        {
        }
        else if (strcmp(argv[i], "--webauthn-rp-id") != 0 &&
                 (strcmp(argv[i], "--target") == 0 || strcmp(argv[i], "--port") == 0 ||
                  strcmp(argv[i], "--user") == 0 || strcmp(argv[i], "--password") == 0 ||
                  strcmp(argv[i], "--domain") == 0 || strcmp(argv[i], "--width") == 0 ||
                  strcmp(argv[i], "--height") == 0 || strcmp(argv[i], "--security") == 0 ||
                  strcmp(argv[i], "--rail") == 0 || strcmp(argv[i], "--gateway") == 0 ||
                  strcmp(argv[i], "--gateway-mode") == 0 || strcmp(argv[i], "--gateway-user") == 0 ||
                  strcmp(argv[i], "--gateway-password") == 0 || strcmp(argv[i], "--gateway-domain") == 0 ||
                  strcmp(argv[i], "--gateway-timeout") == 0))
        {
            if (!cocoa_viewer_need_value(options->argc, &i, argv[i]))
                return 0;
        }
        i++;
    }
    if (librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_WEBAUTHN) &&
        librdp_settings_webauthn_rp_id_count(settings) == 0)
        return 0;
    return 1;
}

static librdp_tls_certificate_decision cocoa_viewer_tls_callback(
    const librdp_tls_certificate_info* certificate,
    void* user_data)
{
    const cocoa_viewer_options* options = (const cocoa_viewer_options*)user_data;
    char answer[16];

    if (!certificate || !options)
        return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;
    fprintf(stderr, "tls_certificate host=\"%s\"\n", certificate->host ? certificate->host : "");
    fprintf(stderr, "tls_certificate subject=\"%s\"\n", certificate->subject ? certificate->subject : "");
    fprintf(stderr, "tls_certificate issuer=\"%s\"\n", certificate->issuer ? certificate->issuer : "");
    fprintf(stderr, "tls_certificate sha256=%s\n", certificate->sha256_fingerprint);
    fprintf(stderr,
            "tls_certificate verify_status=%s native_verify_result=%ld\n",
            librdp_status_name(certificate->verify_status),
            certificate->native_verify_result);
    if (options->tls_accept_any_certificate || options->accept_tls_certificate)
    {
        fprintf(stderr, "tls_certificate decision=accepted mode=auto\n");
        return LIBRDP_TLS_CERTIFICATE_DECISION_ACCEPT;
    }
    if (!options->tls_prompt_certificate)
        return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;
    fprintf(stderr, "Accept this TLS certificate for this connection? [y/N] ");
    fflush(stderr);
    if (!fgets(answer, sizeof(answer), stdin))
        return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;
    if (answer[0] == 'y' || answer[0] == 'Y')
    {
        fprintf(stderr, "tls_certificate decision=accepted mode=prompt\n");
        return LIBRDP_TLS_CERTIFICATE_DECISION_ACCEPT;
    }
    fprintf(stderr, "tls_certificate decision=rejected mode=prompt\n");
    return LIBRDP_TLS_CERTIFICATE_DECISION_REJECT;
}

/*
 * Build the public settings object consumed by the session. All strings
 * accepted from Cocoa CLI parsing are copied by librdp setters before this
 * function returns; certificate callbacks retain only the startup options
 * object for the lifetime of the connection attempt.
 */
static librdp_settings* cocoa_viewer_create_settings(cocoa_viewer_options* options)
{
    librdp_settings* settings = NULL;
    librdp_tls_policy tls_policy;

    if (!options)
        return NULL;
    settings = librdp_settings_new();
    if (!settings)
        return NULL;
    if (librdp_settings_set_target(settings, options->target) != LIBRDP_STATUS_OK ||
        librdp_settings_set_port(settings, options->port) != LIBRDP_STATUS_OK ||
        librdp_settings_set_desktop_size(settings, options->width, options->height) != LIBRDP_STATUS_OK ||
        librdp_settings_set_security_mode(settings, options->security) != LIBRDP_STATUS_OK ||
        librdp_settings_enable_feature(settings, LIBRDP_FEATURE_DISPLAY_CONTROL, 1) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(settings);
        return NULL;
    }
    if (options->username && librdp_settings_set_username(settings, options->username) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(settings);
        return NULL;
    }
    if (options->password && librdp_settings_set_password(settings, options->password) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(settings);
        return NULL;
    }
    if (options->domain && librdp_settings_set_domain(settings, options->domain) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(settings);
        return NULL;
    }
    if (options->rail_app && librdp_settings_add_rail_app(settings, options->rail_app) != LIBRDP_STATUS_OK)
    {
        librdp_settings_free(settings);
        return NULL;
    }
    if (options->gateway_url)
    {
        librdp_gateway_config gateway_config;

        if (librdp_gateway_config_init(&gateway_config) != LIBRDP_STATUS_OK)
        {
            librdp_settings_free(settings);
            return NULL;
        }
        gateway_config.mode = options->gateway_mode;
        gateway_config.url = options->gateway_url;
        gateway_config.username = options->gateway_username;
        gateway_config.password = options->gateway_password;
        gateway_config.domain = options->gateway_domain;
        gateway_config.timeout_ms = options->gateway_has_timeout ? options->gateway_timeout_ms : 0u;
        gateway_config.use_session_credentials = options->gateway_no_session_credentials ? 0 : 1;
        if (librdp_settings_set_gateway_config(settings, &gateway_config) != LIBRDP_STATUS_OK)
        {
            librdp_settings_free(settings);
            return NULL;
        }
    }
    if (options->accept_tls_certificate || options->tls_prompt_certificate || options->tls_accept_any_certificate)
    {
        if (librdp_tls_policy_init(&tls_policy) != LIBRDP_STATUS_OK)
        {
            librdp_settings_free(settings);
            return NULL;
        }
        tls_policy.mode = LIBRDP_TLS_POLICY_TOFU;
        tls_policy.use_system_store = 1;
        tls_policy.certificate_callback = cocoa_viewer_tls_callback;
        tls_policy.certificate_callback_user_data = options;
        if (librdp_settings_set_tls_policy(settings, &tls_policy) != LIBRDP_STATUS_OK)
        {
            librdp_settings_free(settings);
            return NULL;
        }
    }
    if (!cocoa_viewer_apply_feature_args(settings, options))
    {
        librdp_settings_free(settings);
        return NULL;
    }
    return settings;
}

static void cocoa_viewer_graphics_callback(librdp_session* session,
                                           const librdp_graphics_update* update,
                                           void* user_data)
{
    CocoaViewerController* controller = (__bridge CocoaViewerController*)user_data;

    (void)session;
    if (!update || !controller)
        return;
    [controller markDirty];
}

static void cocoa_viewer_pointer_callback(librdp_session* session,
                                          const librdp_event_envelope* envelope,
                                          void* user_data)
{
    CocoaViewerController* controller = (__bridge CocoaViewerController*)user_data;
    const librdp_pointer_event* pointer = NULL;

    (void)session;
    if (!controller || !envelope || envelope->type != LIBRDP_EVENT_POINTER ||
        envelope->payload_size < sizeof(*pointer))
        return;
    pointer = (const librdp_pointer_event*)envelope->payload;
    [controller applyPointerEvent:pointer];
}

static void cocoa_viewer_clipboard_callback(librdp_session* session,
                                            const librdp_event_envelope* envelope,
                                            void* user_data)
{
    CocoaViewerController* controller = (__bridge CocoaViewerController*)user_data;

    (void)session;
    if (!controller || !envelope)
        return;
    [controller handleClipboardEnvelope:envelope];
}

static void cocoa_viewer_audio_callback(librdp_session* session,
                                        const librdp_event_envelope* envelope,
                                        void* user_data)
{
    CocoaViewerController* controller = (__bridge CocoaViewerController*)user_data;

    if (!controller || !session || !envelope)
        return;
    [controller handleAudioEnvelope:session envelope:envelope];
}

static void cocoa_viewer_video_callback(librdp_session* session,
                                        const librdp_event_envelope* envelope,
                                        void* user_data)
{
    CocoaViewerController* controller = (__bridge CocoaViewerController*)user_data;

    if (!controller || !session || !envelope)
        return;
    [controller handleVideoEnvelope:session envelope:envelope];
}

static void cocoa_viewer_channel_callback(librdp_session* session,
                                          const librdp_event_envelope* envelope,
                                          void* user_data)
{
    CocoaViewerController* controller = (__bridge CocoaViewerController*)user_data;

    if (!controller || !session || !envelope)
        return;
    [controller handleChannelEnvelope:session envelope:envelope];
}

static int cocoa_viewer_channel_name_contains(const char* name, size_t name_len, const char* needle)
{
    size_t needle_len = 0;

    if (!name || !needle)
        return 0;
    needle_len = strlen(needle);
    if (needle_len == 0 || needle_len > name_len)
        return 0;
    for (size_t i = 0; i + needle_len <= name_len; i++)
    {
        size_t j = 0;

        for (j = 0; j < needle_len; j++)
        {
            if (tolower((unsigned char)name[i + j]) != tolower((unsigned char)needle[j]))
                break;
        }
        if (j == needle_len)
            return 1;
    }
    return 0;
}

@implementation CocoaViewerView

- (BOOL)isFlipped
{
    return YES;
}

- (BOOL)acceptsFirstResponder
{
    return YES;
}

- (void)resetCursorRects
{
    NSCursor* cursor = self.controller.currentCursor ? self.controller.currentCursor : [NSCursor arrowCursor];

    [self addCursorRect:self.bounds cursor:cursor];
}

- (void)drawRect:(NSRect)dirtyRect
{
    const librdp_surface* surface = NULL;
    librdp_surface_mapping mapping;
    CGColorSpaceRef color_space = NULL;
    CGDataProviderRef provider = NULL;
    CGImageRef image = NULL;
    CGRect destination;
    CGBitmapInfo bitmap_info = (CGBitmapInfo)((uint32_t)kCGBitmapByteOrder32Little |
                                             (uint32_t)kCGImageAlphaNoneSkipFirst);
    librdp_status status = LIBRDP_STATUS_OK;

    (void)dirtyRect;
    if (!self.controller || !self.controller.session)
        return;
    surface = librdp_session_get_surface(self.controller.session);
    if (!surface)
        return;
    if (librdp_surface_mapping_init(&mapping) != LIBRDP_STATUS_OK)
        return;
    status = librdp_surface_map((librdp_surface*)surface, LIBRDP_SURFACE_ACCESS_READ, &mapping);
    if (status != LIBRDP_STATUS_OK || !mapping.pixels)
        return;

    color_space = CGColorSpaceCreateDeviceRGB();
    provider = CGDataProviderCreateWithData(NULL,
                                            mapping.pixels,
                                            mapping.stride * mapping.height,
                                            NULL);
    if (color_space && provider)
        image = CGImageCreate(mapping.width,
                              mapping.height,
                              8,
                              32,
                              mapping.stride,
                              color_space,
                              bitmap_info,
                              provider,
                              NULL,
                              false,
                              kCGRenderingIntentDefault);
    if (image)
    {
        destination = CGRectMake(0.0, 0.0, NSWidth(self.bounds), NSHeight(self.bounds));
        CGContextDrawImage((CGContextRef)[[NSGraphicsContext currentContext] CGContext], destination, image);
    }
    if (image)
        CGImageRelease(image);
    if (provider)
        CGDataProviderRelease(provider);
    if (color_space)
        CGColorSpaceRelease(color_space);
    (void)librdp_surface_unmap((librdp_surface*)surface, &mapping);
}

- (void)mouseMoved:(NSEvent*)event
{
    [self.controller sendMouseEvent:event button:LIBRDP_MOUSE_BUTTON_NONE state:LIBRDP_MOUSE_MOVED];
}

- (void)mouseDragged:(NSEvent*)event
{
    [self mouseMoved:event];
}

- (void)rightMouseDragged:(NSEvent*)event
{
    [self mouseMoved:event];
}

- (void)otherMouseDragged:(NSEvent*)event
{
    [self mouseMoved:event];
}

- (void)mouseDown:(NSEvent*)event
{
    [self.controller sendMouseEvent:event button:LIBRDP_MOUSE_BUTTON_LEFT state:LIBRDP_MOUSE_PRESSED];
}

- (void)mouseUp:(NSEvent*)event
{
    [self.controller sendMouseEvent:event button:LIBRDP_MOUSE_BUTTON_LEFT state:LIBRDP_MOUSE_RELEASED];
}

- (void)rightMouseDown:(NSEvent*)event
{
    [self.controller sendMouseEvent:event button:LIBRDP_MOUSE_BUTTON_RIGHT state:LIBRDP_MOUSE_PRESSED];
}

- (void)rightMouseUp:(NSEvent*)event
{
    [self.controller sendMouseEvent:event button:LIBRDP_MOUSE_BUTTON_RIGHT state:LIBRDP_MOUSE_RELEASED];
}

- (void)otherMouseDown:(NSEvent*)event
{
    NSInteger raw_button_number = [event buttonNumber];
    NSUInteger button_number = 0;
    librdp_mouse_button button = LIBRDP_MOUSE_BUTTON_X2;

    if (raw_button_number < 0)
        return;
    button_number = (NSUInteger)raw_button_number;
    if (button_number == 2)
        button = LIBRDP_MOUSE_BUTTON_MIDDLE;
    else if (button_number == 3)
        button = LIBRDP_MOUSE_BUTTON_X1;

    [self.controller sendMouseEvent:event button:button state:LIBRDP_MOUSE_PRESSED];
}

- (void)otherMouseUp:(NSEvent*)event
{
    NSInteger raw_button_number = [event buttonNumber];
    NSUInteger button_number = 0;
    librdp_mouse_button button = LIBRDP_MOUSE_BUTTON_X2;

    if (raw_button_number < 0)
        return;
    button_number = (NSUInteger)raw_button_number;
    if (button_number == 2)
        button = LIBRDP_MOUSE_BUTTON_MIDDLE;
    else if (button_number == 3)
        button = LIBRDP_MOUSE_BUTTON_X1;

    [self.controller sendMouseEvent:event button:button state:LIBRDP_MOUSE_RELEASED];
}

- (void)scrollWheel:(NSEvent*)event
{
    [self.controller sendWheelEvent:event];
}

- (void)keyDown:(NSEvent*)event
{
    [self.controller sendKeyEvent:event pressed:YES];
}

- (void)keyUp:(NSEvent*)event
{
    [self.controller sendKeyEvent:event pressed:NO];
}

- (void)flagsChanged:(NSEvent*)event
{
    (void)event;
}

@end

@implementation CocoaViewerController

- (id)initWithSession:(librdp_session*)session width:(uint32_t)width height:(uint32_t)height
{
    NSRect frame = NSMakeRect(0.0, 0.0, (CGFloat)width, (CGFloat)height);

    self = [super init];
    if (!self)
        return nil;
    self.session = session;
    self.view = [[CocoaViewerView alloc] initWithFrame:frame];
    self.view.controller = self;
    self.window = [[NSWindow alloc] initWithContentRect:frame
                                              styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                                                        NSWindowStyleMaskResizable | NSWindowStyleMaskMiniaturizable
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
    [self.window setTitle:@"librdp-cocoa-viewer"];
    [self.window setContentView:self.view];
    [self.window setAcceptsMouseMovedEvents:YES];
    [self.window center];
    self.currentCursor = [NSCursor arrowCursor];
    self.pasteboardChangeCount = [[NSPasteboard generalPasteboard] changeCount];
    self.audioOutputCurrentFormat = UINT32_MAX;
    return self;
}

- (BOOL)configureMediaWithOptions:(const cocoa_viewer_options*)options
{
    if (!options)
        return NO;
    self.audioOutputRequested = options->audio_output_requested ? YES : NO;
    self.audioInputRequested = options->audio_input_requested ? YES : NO;
    self.videoRequested = options->video_requested ? YES : NO;
    self.cameraRequested = options->camera_requested ? YES : NO;
    self.audioOutputDevice = options->audio_output_device ? options->audio_output_device : "coreaudio";
    self.audioInputDevice = options->audio_input_device ? options->audio_input_device : "coreaudio";
    self.cameraSource = options->camera_source;
    self.audioOutputCurrentFormat = UINT32_MAX;
    if (self.audioOutputRequested || self.audioInputRequested)
    {
        self.audio = cocoa_audio_backend_new();
        if (!self.audio)
            return NO;
    }
    if (self.videoRequested && options->video_output_path)
    {
        self.videoOutputFile = fopen(options->video_output_path, "ab");
        if (!self.videoOutputFile)
            return NO;
    }
    if (self.cameraRequested)
    {
        self.camera = cocoa_camera_source_new();
        if (!self.camera)
            return NO;
    }
    return YES;
}

- (void)shutdownMedia
{
    if (self.audio)
    {
        cocoa_audio_backend_free(self.audio);
        self.audio = NULL;
    }
    if (self.camera)
    {
        cocoa_camera_source_free(self.camera);
        self.camera = NULL;
    }
    if (self.videoOutputFile)
    {
        fclose(self.videoOutputFile);
        self.videoOutputFile = NULL;
    }
    self.audioInputActive = NO;
    self.audioInputChunk = 0;
    self.audioOutputCurrentFormat = UINT32_MAX;
}

- (void)start
{
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    [self.window makeKeyAndOrderFront:nil];
    [self.window makeFirstResponder:self.view];
    [NSApp activateIgnoringOtherApps:YES];
    self.timer = [NSTimer scheduledTimerWithTimeInterval:0.01
                                                  target:self
                                                selector:@selector(driveSession:)
                                                userInfo:nil
                                                 repeats:YES];
}

- (void)markDirty
{
    self.dirty = YES;
    [self.view setNeedsDisplay:YES];
}

- (size_t)audioInputChunkForOpen:(const librdp_audio_input_open_event*)open
{
    size_t chunk = 0;

    if (!open || open->format.block_align == 0)
        return 0;
    chunk = (size_t)open->frames_per_packet * open->format.block_align;
    if (chunk == 0)
        chunk = open->format.block_align;
    if (chunk > COCOA_AUDIO_INPUT_BUFFER_BYTES)
    {
        chunk = COCOA_AUDIO_INPUT_BUFFER_BYTES -
                (COCOA_AUDIO_INPUT_BUFFER_BYTES % open->format.block_align);
        if (chunk == 0)
            chunk = open->format.block_align;
    }
    return chunk;
}

- (void)storeAudioOutputFormats:(const librdp_audio_output_formats_event*)formats
{
    uint32_t count = 0;

    self.audioOutputFormatCount = 0;
    self.audioOutputCurrentFormat = UINT32_MAX;
    memset(_audioOutputFormats, 0, sizeof(_audioOutputFormats));
    if (!formats || !formats->formats || formats->count == 0)
        return;
    count = formats->count > COCOA_AUDIO_OUTPUT_FORMATS_MAX ?
        COCOA_AUDIO_OUTPUT_FORMATS_MAX :
        formats->count;
    memcpy(_audioOutputFormats, formats->formats, sizeof(_audioOutputFormats[0]) * count);
    self.audioOutputFormatCount = count;
}

- (BOOL)selectAudioOutputFormat:(uint32_t)formatNo
{
    if (!self.audioOutputRequested || !self.audio)
        return NO;
    if (formatNo >= self.audioOutputFormatCount)
        return NO;
    if (self.audioOutputCurrentFormat == formatNo)
        return YES;
    if (!cocoa_audio_backend_start_output(self.audio, &_audioOutputFormats[formatNo], self.audioOutputDevice))
        return NO;
    self.audioOutputCurrentFormat = formatNo;
    return YES;
}

- (void)pumpAudioInput
{
    size_t bytes = 0;

    if (!self.audioInputActive || !self.audio || !self.session || self.audioInputChunk == 0)
        return;
    bytes = cocoa_audio_backend_read_input(self.audio, _audioInputBuffer, self.audioInputChunk);
    if (bytes == 0)
        return;
    if (librdp_session_audio_input_send_data(self.session, _audioInputBuffer, bytes) != LIBRDP_STATUS_OK)
        self.audioInputActive = NO;
}

- (void)handleAudioEnvelope:(librdp_session*)session envelope:(const librdp_event_envelope*)envelope
{
    if (!session || !envelope)
        return;
    switch (envelope->type)
    {
        case LIBRDP_EVENT_AUDIO_OUTPUT_FORMATS:
            if (envelope->payload_size >= sizeof(librdp_audio_output_formats_event))
            {
                [self storeAudioOutputFormats:(const librdp_audio_output_formats_event*)envelope->payload];
                if (self.audioOutputFormatCount > 0)
                    (void)[self selectAudioOutputFormat:0];
            }
            break;
        case LIBRDP_EVENT_AUDIO_OUTPUT_DATA:
            if (envelope->payload_size >= sizeof(librdp_audio_output_data_event))
            {
                const librdp_audio_output_data_event* data =
                    (const librdp_audio_output_data_event*)envelope->payload;

                if ([self selectAudioOutputFormat:data->format_no])
                    (void)cocoa_audio_backend_write_output(self.audio, data->data, data->data_len);
            }
            break;
        case LIBRDP_EVENT_AUDIO_OUTPUT_CLOSE:
            if (self.audio)
                cocoa_audio_backend_stop_output(self.audio);
            self.audioOutputCurrentFormat = UINT32_MAX;
            break;
        case LIBRDP_EVENT_AUDIO_INPUT_OPEN:
            if (envelope->payload_size >= sizeof(librdp_audio_input_open_event))
            {
                const librdp_audio_input_open_event* open =
                    (const librdp_audio_input_open_event*)envelope->payload;
                int ok = 0;

                self.audioInputActive = NO;
                self.audioInputChunk = [self audioInputChunkForOpen:open];
                if (self.audioInputRequested && self.audio && self.audioInputChunk > 0)
                    ok = cocoa_audio_backend_start_input(self.audio, &open->format, self.audioInputDevice);
                (void)librdp_session_audio_input_open_reply(session,
                                                            ok ? LIBRDP_AUDIO_INPUT_RESULT_OK :
                                                                 LIBRDP_AUDIO_INPUT_RESULT_FAIL);
                self.audioInputActive = ok ? YES : NO;
            }
            break;
        default:
            break;
    }
}

- (void)handleVideoEnvelope:(librdp_session*)session envelope:(const librdp_event_envelope*)envelope
{
    if (!session || !envelope)
        return;
    switch (envelope->type)
    {
        case LIBRDP_EVENT_VIDEO_CAPTURE_OPEN:
            if (envelope->payload_size >= sizeof(librdp_video_capture_open_event) &&
                self.cameraRequested && self.camera && self.cameraSource)
            {
                const librdp_video_capture_open_event* open =
                    (const librdp_video_capture_open_event*)envelope->payload;

                (void)cocoa_camera_source_start(self.camera, self.cameraSource, &open->media);
            }
            break;
        case LIBRDP_EVENT_VIDEO_CAPTURE_SAMPLE_REQUEST:
            if (envelope->payload_size >= sizeof(librdp_video_capture_sample_request_event))
            {
                const librdp_video_capture_sample_request_event* request =
                    (const librdp_video_capture_sample_request_event*)envelope->payload;
                uint8_t* sample = NULL;
                size_t sampleLen = 0;
                int sampleResult = 0;

                if (self.cameraRequested && self.camera)
                    sampleResult = cocoa_camera_source_read_sample(self.camera, &sample, &sampleLen);
                if (sampleResult == 1)
                    (void)librdp_session_video_capture_send_sample(session,
                                                                   request->stream_index,
                                                                   sample,
                                                                   sampleLen);
                else
                    (void)librdp_session_video_capture_send_error(
                        session,
                        request->stream_index,
                        sampleResult == 0 ? LIBRDP_VIDEO_CAPTURE_ERROR_NOT_SUPPORTED :
                                            LIBRDP_VIDEO_CAPTURE_ERROR_UNEXPECTED);
                free(sample);
            }
            break;
        case LIBRDP_EVENT_VIDEO_CAPTURE_CLOSE:
            if (self.camera)
                cocoa_camera_source_stop(self.camera);
            break;
        default:
            break;
    }
}

- (void)handleChannelEnvelope:(librdp_session*)session envelope:(const librdp_event_envelope*)envelope
{
    const librdp_channel_data_event* event = NULL;

    (void)session;
    if (!envelope || envelope->type != LIBRDP_EVENT_CHANNEL_DATA ||
        envelope->payload_size < sizeof(*event))
        return;
    event = (const librdp_channel_data_event*)envelope->payload;
    if (self.videoOutputFile &&
        (cocoa_viewer_channel_name_contains(event->name, event->name_len, "video") ||
         cocoa_viewer_channel_name_contains(event->name, event->name_len, "tsmf")) &&
        event->data_len > 0)
    {
        (void)fwrite(event->data, 1, event->data_len, self.videoOutputFile);
        fflush(self.videoOutputFile);
    }
}

- (void)driveSession:(NSTimer*)timer
{
    librdp_status status = LIBRDP_STATUS_OK;
    librdp_session_state state = LIBRDP_SESSION_IDLE;

    (void)timer;
    if (!self.session || self.closed)
        return;
    [self publishLocalPasteboardIfChanged];
    [self pumpAudioInput];
    status = librdp_session_run_once(self.session, 0);
    if (status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_CLOSED)
        fprintf(stderr, "session dispatch failed: %s\n", librdp_status_string(status));
    state = librdp_session_get_state(self.session);
    if (status == LIBRDP_STATUS_CLOSED || state == LIBRDP_SESSION_CLOSED ||
        state == LIBRDP_SESSION_FAILED || state == LIBRDP_SESSION_CANCELLED)
    {
        self.closed = YES;
        [self.timer invalidate];
        self.timer = nil;
        [NSApp terminate:nil];
        return;
    }
    if (self.dirty)
    {
        self.dirty = NO;
        [self.view setNeedsDisplay:YES];
    }
}

- (void)sendResizeForView
{
    NSSize size = self.view.bounds.size;
    uint32_t width = size.width > 1.0 ? (uint32_t)size.width : 1u;
    uint32_t height = size.height > 1.0 ? (uint32_t)size.height : 1u;

    if (!self.session)
        return;
    if (width > 8192u)
        width = 8192u;
    if (height > 8192u)
        height = 8192u;
    (void)librdp_session_resize(self.session, width, height);
}

- (void)sendMouseEvent:(NSEvent*)event button:(librdp_mouse_button)button state:(librdp_mouse_state)state
{
    NSPoint point;
    librdp_mouse_event mouse;

    if (!self.session || !event)
        return;
    point = [self.view convertPoint:[event locationInWindow] fromView:nil];
    memset(&mouse, 0, sizeof(mouse));
    mouse.x = point.x < 0.0 ? 0u : (point.x > 65535.0 ? 65535u : (uint16_t)point.x);
    mouse.y = point.y < 0.0 ? 0u : (point.y > 65535.0 ? 65535u : (uint16_t)point.y);
    mouse.button = button;
    mouse.state = state;
    (void)librdp_session_send_mouse(self.session, &mouse);
}

- (void)sendWheelEvent:(NSEvent*)event
{
    CGFloat delta_x = 0.0;
    CGFloat delta_y = 0.0;

    if (!event)
        return;
    delta_x = [event scrollingDeltaX];
    delta_y = [event scrollingDeltaY];
    if (delta_y > 0.0)
        [self sendMouseEvent:event button:LIBRDP_MOUSE_BUTTON_WHEEL_UP state:LIBRDP_MOUSE_PRESSED];
    else if (delta_y < 0.0)
        [self sendMouseEvent:event button:LIBRDP_MOUSE_BUTTON_WHEEL_DOWN state:LIBRDP_MOUSE_PRESSED];
    if (delta_x > 0.0)
        [self sendMouseEvent:event button:LIBRDP_MOUSE_BUTTON_WHEEL_LEFT state:LIBRDP_MOUSE_PRESSED];
    else if (delta_x < 0.0)
        [self sendMouseEvent:event button:LIBRDP_MOUSE_BUTTON_WHEEL_RIGHT state:LIBRDP_MOUSE_PRESSED];
}

- (void)sendKeyEvent:(NSEvent*)event pressed:(BOOL)pressed
{
    NSString* characters = nil;
    NSUInteger length = 0;
    NSUInteger i = 0;

    if (!self.session || !event)
        return;
    characters = [event characters];
    length = [characters length];
    for (i = 0; i < length; i++)
    {
        librdp_key_event key;

        memset(&key, 0, sizeof(key));
        key.state = pressed ? LIBRDP_KEY_PRESSED : LIBRDP_KEY_RELEASED;
        key.flags = LIBRDP_KEY_FLAG_UNICODE;
        key.unicode = (uint32_t)[characters characterAtIndex:i];
        (void)librdp_session_send_key(self.session, &key);
    }
}

- (NSCursor*)hiddenCursor
{
    NSImage* image = [[NSImage alloc] initWithSize:NSMakeSize(1.0, 1.0)];

    return [[NSCursor alloc] initWithImage:image hotSpot:NSMakePoint(0.0, 0.0)];
}

- (NSCursor*)cursorFromPointer:(const librdp_pointer_event*)pointer
{
    CFDataRef data = NULL;
    CGColorSpaceRef color_space = NULL;
    CGDataProviderRef provider = NULL;
    CGImageRef cg_image = NULL;
    NSImage* image = nil;
    NSCursor* cursor = nil;
    size_t payload_len = 0;
    CGBitmapInfo bitmap_info = (CGBitmapInfo)((uint32_t)kCGBitmapByteOrder32Little |
                                             (uint32_t)kCGImageAlphaPremultipliedFirst);

    if (!pointer || !pointer->pixels || pointer->pixels_len == 0 || pointer->width == 0 || pointer->height == 0 ||
        pointer->stride < (uint32_t)pointer->width * 4u ||
        pointer->pixels_len < (size_t)pointer->stride * (size_t)pointer->height)
        return [NSCursor arrowCursor];

    payload_len = (size_t)pointer->stride * (size_t)pointer->height;
    if (payload_len > (size_t)LONG_MAX)
        return [NSCursor arrowCursor];
    data = CFDataCreate(kCFAllocatorDefault, pointer->pixels, (CFIndex)payload_len);
    color_space = CGColorSpaceCreateDeviceRGB();
    if (data)
        provider = CGDataProviderCreateWithCFData(data);
    if (color_space && provider)
        cg_image = CGImageCreate(pointer->width,
                                 pointer->height,
                                 8,
                                 32,
                                 pointer->stride,
                                 color_space,
                                 bitmap_info,
                                 provider,
                                 NULL,
                                 false,
                                 kCGRenderingIntentDefault);
    if (cg_image)
        image = [[NSImage alloc] initWithCGImage:cg_image
                                           size:NSMakeSize((CGFloat)pointer->width, (CGFloat)pointer->height)];
    if (image)
        cursor = [[NSCursor alloc] initWithImage:image
                                         hotSpot:NSMakePoint((CGFloat)pointer->hot_x, (CGFloat)pointer->hot_y)];
    if (cg_image)
        CGImageRelease(cg_image);
    if (provider)
        CGDataProviderRelease(provider);
    if (color_space)
        CGColorSpaceRelease(color_space);
    if (data)
        CFRelease(data);
    return cursor ? cursor : [NSCursor arrowCursor];
}

- (void)setCurrentCursor:(NSCursor*)cursor
{
    _currentCursor = cursor ? cursor : [NSCursor arrowCursor];
    [_currentCursor set];
    [self.window invalidateCursorRectsForView:self.view];
}

- (void)applyPointerEvent:(const librdp_pointer_event*)pointer
{
    if (!pointer)
        return;
    switch (pointer->update_type)
    {
        case LIBRDP_POINTER_UPDATE_DEFAULT:
            [self setCurrentCursor:[NSCursor arrowCursor]];
            break;
        case LIBRDP_POINTER_UPDATE_HIDDEN:
            [self setCurrentCursor:[self hiddenCursor]];
            break;
        case LIBRDP_POINTER_UPDATE_SHAPE:
            [self setCurrentCursor:[self cursorFromPointer:pointer]];
            break;
        case LIBRDP_POINTER_UPDATE_POSITION:
            break;
    }
}

- (void)publishLocalPasteboardIfChanged
{
    NSPasteboard* pasteboard = [NSPasteboard generalPasteboard];
    NSString* string = nil;
    NSData* utf16 = nil;

    if (!self.session || !pasteboard || [pasteboard changeCount] == self.pasteboardChangeCount)
        return;
    self.pasteboardChangeCount = [pasteboard changeCount];
    string = [pasteboard stringForType:NSPasteboardTypeString];
    if (!string)
    {
        (void)librdp_session_clipboard_clear(self.session);
        return;
    }
    utf16 = [string dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
    if (!utf16)
        return;
    (void)librdp_session_clipboard_set_data(self.session,
                                            LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT,
                                            [utf16 bytes],
                                            [utf16 length]);
}

- (void)writeStringToPasteboard:(NSString*)string type:(NSPasteboardType)type
{
    NSPasteboard* pasteboard = [NSPasteboard generalPasteboard];

    if (!pasteboard || !string)
        return;
    [pasteboard clearContents];
    [pasteboard setString:string forType:type];
    self.pasteboardChangeCount = [pasteboard changeCount];
}

- (void)writeDataToPasteboard:(NSData*)data type:(NSPasteboardType)type
{
    NSPasteboard* pasteboard = [NSPasteboard generalPasteboard];

    if (!pasteboard || !data)
        return;
    [pasteboard clearContents];
    [pasteboard setData:data forType:type];
    self.pasteboardChangeCount = [pasteboard changeCount];
}

- (void)handleRemoteFormats:(const librdp_clipboard_formats_event*)formats
{
    uint32_t i = 0;

    if (!self.session || !formats || !formats->formats)
        return;
    for (i = 0; i < formats->count; i++)
    {
        uint32_t format_id = formats->formats[i].format_id;

        if (format_id == LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT || format_id == LIBRDP_CLIPBOARD_FORMAT_TEXT ||
            format_id == LIBRDP_CLIPBOARD_FORMAT_PNG || format_id == LIBRDP_CLIPBOARD_FORMAT_HTML)
        {
            (void)librdp_session_clipboard_request_data(self.session, format_id);
            return;
        }
    }
}

- (void)handleRemoteClipboardData:(const librdp_clipboard_data_event*)data
{
    NSData* ns_data = nil;
    NSString* string = nil;

    if (!data || !data->ok || !data->data || data->data_len == 0)
        return;
    ns_data = [NSData dataWithBytes:data->data length:data->data_len];
    if (!ns_data)
        return;
    if (data->format_id == LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT)
    {
        string = [[NSString alloc] initWithBytes:data->data
                                          length:data->data_len
                                        encoding:NSUTF16LittleEndianStringEncoding];
        [self writeStringToPasteboard:string type:NSPasteboardTypeString];
    }
    else if (data->format_id == LIBRDP_CLIPBOARD_FORMAT_TEXT)
    {
        string = [[NSString alloc] initWithData:ns_data encoding:NSUTF8StringEncoding];
        if (!string)
            string = [[NSString alloc] initWithData:ns_data encoding:NSISOLatin1StringEncoding];
        [self writeStringToPasteboard:string type:NSPasteboardTypeString];
    }
    else if (data->format_id == LIBRDP_CLIPBOARD_FORMAT_HTML)
    {
        string = [[NSString alloc] initWithData:ns_data encoding:NSUTF8StringEncoding];
        [self writeStringToPasteboard:string type:NSPasteboardTypeHTML];
    }
    else if (data->format_id == LIBRDP_CLIPBOARD_FORMAT_PNG)
        [self writeDataToPasteboard:ns_data type:NSPasteboardTypePNG];
}

- (void)handleClipboardEnvelope:(const librdp_event_envelope*)envelope
{
    if (!envelope || !envelope->payload)
        return;
    switch (envelope->type)
    {
        case LIBRDP_EVENT_CLIPBOARD_FORMATS:
            if (envelope->payload_size >= sizeof(librdp_clipboard_formats_event))
                [self handleRemoteFormats:(const librdp_clipboard_formats_event*)envelope->payload];
            break;
        case LIBRDP_EVENT_CLIPBOARD_DATA:
            if (envelope->payload_size >= sizeof(librdp_clipboard_data_event))
                [self handleRemoteClipboardData:(const librdp_clipboard_data_event*)envelope->payload];
            break;
        case LIBRDP_EVENT_CLIPBOARD_REQUEST:
            [self publishLocalPasteboardIfChanged];
            break;
        default:
            break;
    }
}

@end

int main(int argc, char** argv)
{
    cocoa_viewer_options options;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    CocoaViewerController* controller = nil;
    librdp_status status = LIBRDP_STATUS_OK;
    int exit_code = 1;

    @autoreleasepool
    {
        if (!cocoa_viewer_parse_args(argc, argv, &options))
        {
            cocoa_viewer_usage(stderr, argv[0]);
            return 2;
        }
        if (options.show_help)
        {
            cocoa_viewer_usage(stdout, argv[0]);
            return 0;
        }
        settings = cocoa_viewer_create_settings(&options);
        if (!settings)
        {
            fprintf(stderr, "failed to create settings\n");
            return 1;
        }
        session = librdp_session_new(settings);
        librdp_settings_free(settings);
        if (!session)
        {
            fprintf(stderr, "failed to create session\n");
            return 1;
        }
        controller = [[CocoaViewerController alloc] initWithSession:session width:options.width height:options.height];
        if (!controller)
        {
            fprintf(stderr, "failed to create viewer window\n");
            librdp_session_free(session);
            return 1;
        }
        if (![controller configureMediaWithOptions:&options])
        {
            fprintf(stderr, "failed to configure media backends\n");
            [controller shutdownMedia];
            librdp_session_free(session);
            return 1;
        }
        librdp_session_set_graphics_update_callback(session, cocoa_viewer_graphics_callback, (__bridge void*)controller);
        librdp_session_set_pointer_callback(session, cocoa_viewer_pointer_callback, (__bridge void*)controller);
        librdp_session_set_channel_callback(session, cocoa_viewer_channel_callback, (__bridge void*)controller);
        librdp_session_set_clipboard_callback(session, cocoa_viewer_clipboard_callback, (__bridge void*)controller);
        librdp_session_set_audio_callback(session, cocoa_viewer_audio_callback, (__bridge void*)controller);
        librdp_session_set_video_callback(session, cocoa_viewer_video_callback, (__bridge void*)controller);
        status = librdp_session_connect(session);
        if (status != LIBRDP_STATUS_OK)
        {
            fprintf(stderr, "connect failed: %s\n", librdp_status_string(status));
            [controller shutdownMedia];
            librdp_session_free(session);
            return 1;
        }
        [NSApplication sharedApplication];
        [controller start];
        [NSApp run];
        (void)librdp_session_disconnect(session);
        [controller shutdownMedia];
        librdp_session_free(session);
        exit_code = 0;
    }
    return exit_code;
}
