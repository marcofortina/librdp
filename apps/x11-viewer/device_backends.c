/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: viewer-side host device backend wiring for optional redirected
 * devices.
 * Invariants: viewer state, X11 resources, and session callbacks are kept
 * consistent with focus and resize events.
 * Ownership: backend handles are owned by viewer settings and released during
 * viewer shutdown.
 * Threading: called from the viewer event thread unless a backend explicitly
 * documents its own callback thread.
 * Trust boundary: command-line options, local devices, X11 events, and server
 * callbacks are separate trust domains.
 */


#include "device_backends.h"

#include "viewer_trace.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <linux/videodev2.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

#ifdef LIBRDP_HAVE_LIBUSB
#include <libusb-1.0/libusb.h>
#endif

#ifdef LIBRDP_HAVE_PCSC
#include <winscard.h>
#endif

#ifdef LIBRDP_HAVE_FIDO2
#include <fido.h>
#endif

static int x11_text_starts_with(const char* text, const char* prefix)
{
    const size_t prefix_len = prefix ? strlen(prefix) : 0;

    if (!text || !prefix)
        return 0;
    return strncmp(text, prefix, prefix_len) == 0;
}

static const char* x11_text_after(const char* text, const char* prefix)
{
    if (!x11_text_starts_with(text, prefix))
        return NULL;
    if (text[strlen(prefix)] == '\0')
        return NULL;
    return text + strlen(prefix);
}

static const char* x11_device_source_path(const char* source)
{
    const char* value = NULL;

    value = x11_text_after(source, "device=");
    if (value)
        return value;
    value = x11_text_after(source, "file=");
    if (value)
        return value;
    return source;
}

static int x11_probe_file_readable(const char* path, const char* event_name)
{
    int fd = -1;
    uint8_t buffer[256];
    ssize_t read_bytes = 0;

    if (!path || path[0] == '\0')
        return 0;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        x11_trace_event(X11_TRACE_CLIENT,
                        event_name,
                        "ok=0 path=\"%s\" errno=%d",
                        path,
                        errno);
        return 0;
    }
    read_bytes = read(fd, buffer, sizeof(buffer));
    close(fd);
    if (read_bytes < 0)
    {
        x11_trace_event(X11_TRACE_CLIENT,
                        event_name,
                        "ok=0 path=\"%s\" errno=%d",
                        path,
                        errno);
        return 0;
    }
    x11_trace_event(X11_TRACE_CLIENT,
                    event_name,
                    "ok=1 path=\"%s\" bytes=%u",
                    path,
                    (unsigned)read_bytes);
    return 1;
}

static int x11_probe_open_path(const char* path, int flags, const char* event_name)
{
    int fd = -1;

    if (!path || path[0] == '\0')
        return 0;
    fd = open(path, flags | O_CLOEXEC);
    if (fd < 0)
    {
        x11_trace_event(X11_TRACE_CLIENT,
                        event_name,
                        "ok=0 path=\"%s\" errno=%d",
                        path,
                        errno);
        return 0;
    }
    close(fd);
    x11_trace_event(X11_TRACE_CLIENT, event_name, "ok=1 path=\"%s\"", path);
    return 1;
}

static int x11_probe_serial_port(const char* path)
{
#ifdef O_NOCTTY
    return x11_probe_open_path(path, O_RDWR | O_NOCTTY | O_NONBLOCK, "x11.serial.probe");
#else
    return x11_probe_open_path(path, O_RDWR | O_NONBLOCK, "x11.serial.probe");
#endif
}

static int x11_probe_parallel_port(const char* path)
{
    if (x11_probe_open_path(path, O_RDWR | O_NONBLOCK, "x11.parallel.probe"))
        return 1;
    return x11_probe_open_path(path, O_WRONLY | O_NONBLOCK, "x11.parallel.probe");
}

static int x11_probe_camera(const char* source)
{
#ifdef __linux__
    const char* path = x11_device_source_path(source);
    int fd = -1;
    struct v4l2_capability capability;

    if (!path || path[0] == '\0')
        return 0;
    if (!x11_text_starts_with(path, "/dev/video"))
        return x11_probe_file_readable(path, "x11.camera.file.probe");

    fd = open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
    {
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.camera.v4l2.probe",
                        "ok=0 source=\"%s\" errno=%d",
                        path,
                        errno);
        return 0;
    }
    memset(&capability, 0, sizeof(capability));
    if (ioctl(fd, VIDIOC_QUERYCAP, &capability) < 0)
    {
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.camera.v4l2.probe",
                        "ok=0 source=\"%s\" errno=%d",
                        path,
                        errno);
        close(fd);
        return 0;
    }
    close(fd);
    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.camera.v4l2.probe",
                    "ok=1 source=\"%s\" driver=\"%s\" card=\"%s\" bus=\"%s\" caps=%u device_caps=%u",
                    path,
                    capability.driver,
                    capability.card,
                    capability.bus_info,
                    capability.capabilities,
                    capability.device_caps);
    return 1;
#else
    return x11_probe_file_readable(source, "x11.camera.file.probe");
#endif
}

static int x11_probe_vsmartcard_socket(const char* path)
{
#ifdef __linux__
    int fd = -1;
    struct sockaddr_un address;
    int ok = 0;

    if (!path || path[0] != '/')
        return 0;
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return 0;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(address.sun_path))
    {
        close(fd);
        return 0;
    }
    memcpy(address.sun_path, path, strlen(path) + 1u);
    ok = connect(fd, (const struct sockaddr*)&address, sizeof(address)) == 0;
    close(fd);
    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.smartcard.vsmartcard.probe",
                    "ok=%u path=\"%s\" errno=%d",
                    ok ? 1u : 0u,
                    path,
                    ok ? 0 : errno);
    return ok;
#else
    (void)path;
    return 0;
#endif
}

static int x11_probe_pcsc(void)
{
#ifdef LIBRDP_HAVE_PCSC
    SCARDCONTEXT context = 0;
    LONG status = SCARD_S_SUCCESS;
    DWORD readers_len = 0;
    char* readers = NULL;
    uint32_t count = 0;
    char* cursor = NULL;

    status = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &context);
    if (status != SCARD_S_SUCCESS)
    {
        x11_trace_event(X11_TRACE_CLIENT, "x11.smartcard.pcsc.probe", "ok=0 stage=context status=%ld", status);
        return 0;
    }
    status = SCardListReaders(context, NULL, NULL, &readers_len);
    if (status != SCARD_S_SUCCESS || readers_len == 0)
    {
        x11_trace_event(X11_TRACE_CLIENT, "x11.smartcard.pcsc.probe", "ok=0 stage=list status=%ld", status);
        SCardReleaseContext(context);
        return 0;
    }
    readers = (char*)calloc(1, readers_len);
    if (!readers)
    {
        SCardReleaseContext(context);
        return 0;
    }
    status = SCardListReaders(context, NULL, readers, &readers_len);
    if (status == SCARD_S_SUCCESS)
    {
        cursor = readers;
        while (*cursor)
        {
            count++;
            cursor += strlen(cursor) + 1u;
        }
    }
    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.smartcard.pcsc.probe",
                    "ok=%u readers=%u status=%ld",
                    status == SCARD_S_SUCCESS && count > 0 ? 1u : 0u,
                    count,
                    status);
    free(readers);
    SCardReleaseContext(context);
    return status == SCARD_S_SUCCESS && count > 0;
#else
    x11_trace_event(X11_TRACE_CLIENT, "x11.smartcard.pcsc.probe", "ok=0 reason=pcsc_unavailable");
    return 0;
#endif
}

static int x11_probe_smartcard(const char* source)
{
    const char* path = x11_text_after(source, "vsmartcard=");

    if (path)
        return x11_probe_vsmartcard_socket(path);
    if (!source || strcmp(source, "pcsc") == 0)
        return x11_probe_pcsc();
    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.smartcard.probe",
                    "ok=0 source=\"%s\" reason=rejected_source",
                    source ? source : "");
    return 0;
}

#ifdef LIBRDP_HAVE_LIBUSB
static int x11_parse_pair(const char* text, unsigned int* first, unsigned int* second, int* decimal_only)
{
    char* end = NULL;
    unsigned long a = 0;
    unsigned long b = 0;
    const char* separator = NULL;
    const char* p = NULL;
    int has_hex_alpha = 0;

    if (!text || !first || !second || !decimal_only)
        return 0;
    separator = strchr(text, ':');
    if (!separator || separator == text || separator[1] == '\0')
        return 0;
    for (p = text; *p; p++)
    {
        if ((*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F') || *p == 'x' || *p == 'X')
            has_hex_alpha = 1;
    }
    a = strtoul(text, &end, has_hex_alpha ? 16 : 10);
    if (end != separator)
        return 0;
    b = strtoul(separator + 1, &end, has_hex_alpha ? 16 : 10);
    if (!end || *end != '\0' || a > 0xfffful || b > 0xfffful)
        return 0;
    *first = (unsigned int)a;
    *second = (unsigned int)b;
    *decimal_only = !has_hex_alpha;
    return 1;
}

static int x11_probe_usb(const char* selector)
{
    libusb_context* context = NULL;
    libusb_device** list = NULL;
    ssize_t count = 0;
    ssize_t i = 0;
    unsigned int first = 0;
    unsigned int second = 0;
    int decimal_only = 0;
    int found = 0;
    int bus_mode = 0;

    if (!x11_parse_pair(selector, &first, &second, &decimal_only))
    {
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.usb.probe",
                        "ok=0 selector=\"%s\" reason=invalid_selector",
                        selector ? selector : "");
        return 0;
    }
    bus_mode = decimal_only && first <= 255u && second <= 255u && strlen(selector) <= 7u;
    if (libusb_init(&context) != 0)
    {
        x11_trace_event(X11_TRACE_CLIENT, "x11.usb.probe", "ok=0 selector=\"%s\" reason=init", selector);
        return 0;
    }
    count = libusb_get_device_list(context, &list);
    if (count < 0)
    {
        x11_trace_event(X11_TRACE_CLIENT, "x11.usb.probe", "ok=0 selector=\"%s\" reason=list", selector);
        libusb_exit(context);
        return 0;
    }
    for (i = 0; i < count && !found; i++)
    {
        libusb_device* device = list[i];

        if (bus_mode)
        {
            found = libusb_get_bus_number(device) == first && libusb_get_device_address(device) == second;
        }
        else
        {
            struct libusb_device_descriptor descriptor;

            if (libusb_get_device_descriptor(device, &descriptor) == 0)
                found = descriptor.idVendor == first && descriptor.idProduct == second;
        }
    }
    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.usb.probe",
                    "ok=%u selector=\"%s\" mode=%s devices=%d",
                    found ? 1u : 0u,
                    selector,
                    bus_mode ? "busdev" : "vidpid",
                    (int)count);
    libusb_free_device_list(list, 1);
    libusb_exit(context);
    return found;
}
#else
static int x11_probe_usb(const char* selector)
{
    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.usb.probe",
                    "ok=0 selector=\"%s\" reason=libusb_unavailable",
                    selector ? selector : "");
    return 0;
}
#endif

static int x11_probe_webauthn(const char* provider)
{
    const char* mock_path = x11_text_after(provider, "mock=");
    const char* fido2_path = x11_text_after(provider, "fido2=");

    if (!provider || strcmp(provider, "mock") == 0)
    {
        x11_trace_event(X11_TRACE_CLIENT, "x11.webauthn.mock.probe", "ok=1 provider=mock");
        return 1;
    }
    if (mock_path)
        return x11_probe_file_readable(mock_path, "x11.webauthn.mock.probe");
    if (strcmp(provider, "fido2") == 0 || fido2_path)
    {
#ifdef LIBRDP_HAVE_FIDO2
        fido_dev_info_t* info = NULL;
        size_t found = 0;
        size_t i = 0;
        int ok = 0;

        fido_init(0);
        info = fido_dev_info_new(64);
        if (info && fido_dev_info_manifest(info, 64, &found) == FIDO_OK)
        {
            if (!fido2_path)
                ok = found > 0 ? 1 : 0;
            else
            {
                for (i = 0; i < found; i++)
                {
                    const fido_dev_info_t* entry = fido_dev_info_ptr(info, i);
                    const char* path = entry ? fido_dev_info_path(entry) : NULL;

                    if (path && strcmp(path, fido2_path) == 0)
                    {
                        ok = 1;
                        break;
                    }
                }
            }
        }
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.webauthn.fido2.probe",
                        "ok=%u provider=\"%s\" devices=%u",
                        ok ? 1u : 0u,
                        provider,
                        (unsigned)found);
        fido_dev_info_free(&info, 64);
        return ok;
#else
        x11_trace_event(X11_TRACE_CLIENT,
                        "x11.webauthn.fido2.probe",
                        "ok=0 provider=\"%s\" reason=fido2_unavailable",
                        provider);
        return 0;
#endif
    }
    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.webauthn.probe",
                    "ok=0 provider=\"%s\" reason=rejected_provider",
                    provider);
    return 0;
}

static int x11_probe_pnp(librdp_settings* settings)
{
    const uint32_t configured = settings ? librdp_settings_pnp_device_count(settings) : 0;

    if (!settings)
        return 0;
    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.pnp.probe",
                    "ok=1 configured=%u autodiscovery=0",
                    configured);
    return 1;
}

static void x11_probe_cr2(uint32_t width, uint32_t height)
{
    x11_trace_event(X11_TRACE_CLIENT,
                    "x11.cr2.compositor.init",
                    "root=1 width=%u height=%u layers=1",
                    width,
                    height);
}

int x11_device_backends_probe(librdp_settings* settings)
{
    uint32_t i = 0;

    if (!settings)
        return 0;
    if (librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_CAMERA))
    {
        for (i = 0; i < librdp_settings_camera_count(settings); i++)
        {
            if (!x11_probe_camera(librdp_settings_camera_source(settings, i)))
                return 0;
        }
    }
    for (i = 0; i < librdp_settings_serial_port_count(settings); i++)
    {
        if (!x11_probe_serial_port(librdp_settings_serial_port_path(settings, i)))
            return 0;
    }
    for (i = 0; i < librdp_settings_parallel_port_count(settings); i++)
    {
        if (!x11_probe_parallel_port(librdp_settings_parallel_port_path(settings, i)))
            return 0;
    }
    if (librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_SMARTCARD))
    {
        if (librdp_settings_smartcard_count(settings) == 0)
        {
            if (!x11_probe_smartcard("pcsc"))
                return 0;
        }
        for (i = 0; i < librdp_settings_smartcard_count(settings); i++)
        {
            if (!x11_probe_smartcard(librdp_settings_smartcard_source(settings, i)))
                return 0;
        }
    }
    if (librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_USB))
    {
        for (i = 0; i < librdp_settings_usb_device_count(settings); i++)
        {
            if (!x11_probe_usb(librdp_settings_usb_device_selector(settings, i)))
                return 0;
        }
    }
    if (librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_WEBAUTHN))
    {
        if (!x11_probe_webauthn(librdp_settings_webauthn_provider(settings)))
            return 0;
    }
    if (librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_PNP) && !x11_probe_pnp(settings))
        return 0;
    if (librdp_settings_feature_enabled(settings, LIBRDP_FEATURE_CR2))
        x11_probe_cr2(librdp_settings_width(settings), librdp_settings_height(settings));
    return 1;
}
