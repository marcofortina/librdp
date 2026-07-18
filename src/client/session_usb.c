/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client USB redirection session domain.
 * Invariants: URBDRC packets are header-validated before backend execution and interface IDs remain session-owned.
 * Ownership: the session owns announced USB backend handles, transfer buffers, and DVC completion routing state.
 * Threading: called on the session owner thread; backend calls must not publish raw payloads through trace.
 * Trust boundary: server-supplied URBs are untrusted and all lengths, offsets, pipe handles, and descriptor requests are bounded.
 */

#include "client/session_internal.h"

#include "common/charset.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef RDP_HAVE_LIBUSB
#include <libusb.h>
#endif

void rdp_session_usb_redirection_reset(librdp_session* session)
{
    if (!session)
        return;
#ifdef RDP_HAVE_LIBUSB
    rdp_usb_backend_release_devices(session->usb_devices, LIBRDP_SETTINGS_MAX_USB_DEVICES);
    rdp_usb_backend_context_exit(&session->usb_libusb);
#endif
    session->usb_redirection_channel_id = 0;
    session->usb_redirection_channel_id_bytes = 0;
    session->usb_redirection_ready = 0;
    session->usb_request_completion_ready = 0;
    session->usb_message_id = 0;
    session->usb_request_completion_interface_id = 0;
    session->usb_device_count_sent = 0;
}

static uint32_t rdp_session_usb_next_message_id(librdp_session* session)
{
    if (!session)
        return 0;
    session->usb_message_id++;
    if (session->usb_message_id == 0)
        session->usb_message_id++;
    return session->usb_message_id;
}

static librdp_status rdp_session_usb_checked_format(char* out, size_t out_len, const char* fmt, unsigned a, unsigned b, unsigned c)
{
    int written = 0;

    if (!out || out_len == 0 || !fmt)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    written = snprintf(out, out_len, fmt, a, b, c);
    if (written <= 0 || (size_t)written >= out_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_usb_multisz2(rdp_buffer* out, const char* first, const char* second);

#ifdef RDP_HAVE_LIBUSB
static librdp_status rdp_session_usb_libusb_find(librdp_session* session,
                                                 const char* selector,
                                                 uint32_t interface_id,
                                                 rdp_usb_backend_device* out)
{
    const librdp_usb_policy* policy = NULL;
    rdp_usb_backend_open_request request;
    rdp_usb_backend_match match;
    librdp_usb_selector_mode mode = LIBRDP_USB_SELECTOR_VID_PID;
    uint32_t first = 0;
    uint32_t second = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !selector || !out)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    memset(&request, 0, sizeof(request));
    memset(&match, 0, sizeof(match));
    status = librdp_usb_selector_parse(selector, &mode, &first, &second);
    if (status != LIBRDP_STATUS_OK)
        return status;
    policy = rdp_settings_usb_policy_internal(session->settings);
    if (!policy)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    request.first = first;
    request.second = second;
    request.interface_id = interface_id;
    request.bus_mode = mode == LIBRDP_USB_SELECTOR_BUS_DEV;
    request.allow_hid = policy->allow_hid;
    request.allow_mass_storage = policy->allow_mass_storage;
    status = rdp_usb_backend_open_device(&session->usb_libusb, &request, out, &match);
    if (status == LIBRDP_STATUS_STATE)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.policy.denied",
                        "selector=\"%s\" vid=%04x pid=%04x class=%u bus=%u address=%u",
                        selector,
                        (unsigned)match.vendor_id,
                        (unsigned)match.product_id,
                        match.device_class,
                        match.bus_number,
                        match.device_address);
    }
    return status;
}

static librdp_status rdp_session_usb_build_descriptor_device_strings(
    const struct libusb_device_descriptor* descriptor,
    uint32_t index,
    rdp_buffer* instance,
    rdp_buffer* hardware,
    rdp_buffer* compatibility,
    rdp_buffer* container)
{
    char instance_text[96];
    char hardware_first[96];
    char hardware_second[96];
    char compatibility_first[96];
    char compatibility_second[96];
    char container_text[48];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!descriptor || !instance || !hardware || !compatibility || !container)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_usb_checked_format(instance_text,
                                            sizeof(instance_text),
                                            "USB\\VID_%04X&PID_%04X\\RDP_%02u",
                                            descriptor->idVendor,
                                            descriptor->idProduct,
                                            (unsigned)index + 1u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_checked_format(hardware_first,
                                                sizeof(hardware_first),
                                                "USB\\VID_%04X&PID_%04X&REV_%04X",
                                                descriptor->idVendor,
                                                descriptor->idProduct,
                                                descriptor->bcdDevice);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_checked_format(hardware_second,
                                                sizeof(hardware_second),
                                                "USB\\VID_%04X&PID_%04X",
                                                descriptor->idVendor,
                                                descriptor->idProduct,
                                                0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_checked_format(compatibility_first,
                                                sizeof(compatibility_first),
                                                "USB\\Class_%02X&SubClass_%02X&Prot_%02X",
                                                descriptor->bDeviceClass,
                                                descriptor->bDeviceSubClass,
                                                descriptor->bDeviceProtocol);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_checked_format(compatibility_second,
                                                sizeof(compatibility_second),
                                                "USB\\Class_%02X",
                                                descriptor->bDeviceClass,
                                                0,
                                                0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_checked_format(container_text,
                                                sizeof(container_text),
                                                "{00000000-0000-0000-0000-00000000%04X}",
                                                (unsigned)(index + 1u),
                                                0,
                                                0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_utf8_to_utf16le(instance_text, instance, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_multisz2(hardware, hardware_first, hardware_second);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_multisz2(compatibility, compatibility_first, compatibility_second);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_utf8_to_utf16le(container_text, container, 1);
    return status;
}
#endif

static librdp_status rdp_session_usb_multisz2(rdp_buffer* out, const char* first, const char* second)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!out || !first || !second)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_utf8_to_utf16le(first, out, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_utf8_to_utf16le(second, out, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(out, 0);
    return status;
}

/*
 * Build USB device string descriptors for announcement packets. Host
 * descriptor data is copied and length-bounded before it becomes part of the
 * session-owned USB device table.
 */
static librdp_status rdp_session_usb_build_device_strings(const char* selector,
                                                          uint32_t index,
                                                          rdp_buffer* instance,
                                                          rdp_buffer* hardware,
                                                          rdp_buffer* compatibility,
                                                          rdp_buffer* container)
{
    librdp_usb_selector_mode mode = LIBRDP_USB_SELECTOR_VID_PID;
    uint32_t first = 0;
    uint32_t second = 0;
    char instance_text[96];
    char hardware_first[96];
    char hardware_second[96];
    char container_text[48];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!selector || !instance || !hardware || !compatibility || !container)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = librdp_usb_selector_parse(selector, &mode, &first, &second);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (mode == LIBRDP_USB_SELECTOR_BUS_DEV)
    {
        status = rdp_session_usb_checked_format(instance_text,
                                                sizeof(instance_text),
                                                "USB\\BUS_%03u&DEV_%03u\\RDP_%02u",
                                                (unsigned)first,
                                                (unsigned)second,
                                                (unsigned)index + 1u);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_usb_checked_format(hardware_first,
                                                    sizeof(hardware_first),
                                                    "USB\\BUS_%03u&DEV_%03u",
                                                    (unsigned)first,
                                                    (unsigned)second,
                                                    0);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_usb_checked_format(hardware_second,
                                                    sizeof(hardware_second),
                                                    "USB\\Class_00&SubClass_00&Prot_%02u",
                                                    0,
                                                    0,
                                                    0);
    }
    else
    {
        status = rdp_session_usb_checked_format(instance_text,
                                                sizeof(instance_text),
                                                "USB\\VID_%04X&PID_%04X\\RDP_%02u",
                                                (unsigned)first,
                                                (unsigned)second,
                                                (unsigned)index + 1u);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_usb_checked_format(hardware_first,
                                                    sizeof(hardware_first),
                                                    "USB\\VID_%04X&PID_%04X&REV_%04u",
                                                    (unsigned)first,
                                                    (unsigned)second,
                                                    0);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_usb_checked_format(hardware_second,
                                                    sizeof(hardware_second),
                                                    "USB\\VID_%04X&PID_%04X",
                                                    (unsigned)first,
                                                    (unsigned)second,
                                                    0);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_checked_format(container_text,
                                                sizeof(container_text),
                                                "{00000000-0000-0000-0000-00000000%04X}",
                                                (unsigned)(index + 1u),
                                                0,
                                                0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_utf8_to_utf16le(instance_text, instance, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_multisz2(hardware, hardware_first, hardware_second);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_multisz2(compatibility,
                                          "USB\\Class_00&SubClass_00&Prot_00",
                                          "USB\\Class_00");
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_utf8_to_utf16le(container_text, container, 1);
    return status;
}

static librdp_status rdp_session_send_usb_redirection_packet(librdp_session* session,
                                                             const rdp_buffer* packet,
                                                             const char* event)
{
    if (!session || !packet || !event || session->usb_redirection_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_session_send_dynamic_channel_data(session,
                                                 session->usb_redirection_channel_id,
                                                 session->usb_redirection_channel_id_bytes,
                                                 packet->data,
                                                 packet->length,
                                                 event);
}

/*
 * Announce configured USB devices to the server. Device identities,
 * interfaces, and endpoint metadata are snapshotted so backend hotplug changes
 * cannot corrupt in-flight packets or break announcement ordering invariants.
 */
static librdp_status rdp_session_usb_send_device_announcements(librdp_session* session)
{
    uint32_t count = 0;
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_USB))
        return LIBRDP_STATUS_OK;

    count = librdp_settings_usb_device_count(session->settings);
    for (i = 0; i < count && status == LIBRDP_STATUS_OK; i++)
    {
        rdp_buffer packet;
        rdp_buffer instance;
        rdp_buffer hardware;
        rdp_buffer compatibility;
        rdp_buffer container;
        rdp_usb_redirection_device_capabilities capabilities;
        uint32_t interface_id = RDP_SESSION_USB_DEVICE_INTERFACE_BASE + i;
        const char* selector = librdp_settings_usb_device_selector(session->settings, i);
#ifdef RDP_HAVE_LIBUSB
        rdp_usb_backend_device backend_device;
        int have_backend_device = 0;
        const char* backend_name = NULL;
#endif

        rdp_buffer_init(&packet);
        rdp_buffer_init(&instance);
        rdp_buffer_init(&hardware);
        rdp_buffer_init(&compatibility);
        rdp_buffer_init(&container);
#ifdef RDP_HAVE_LIBUSB
        memset(&backend_device, 0, sizeof(backend_device));
        if (rdp_session_usb_libusb_find(session, selector, interface_id, &backend_device) == LIBRDP_STATUS_OK)
        {
            session->usb_devices[i] = backend_device;
            have_backend_device = 1;
        }
        else
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.urbdrc.backend.missing",
                            "selector=\"%s\" interface_id=%u",
                            selector ? selector : "",
                            interface_id);
            rdp_buffer_free(&container);
            rdp_buffer_free(&compatibility);
            rdp_buffer_free(&hardware);
            rdp_buffer_free(&instance);
            rdp_buffer_free(&packet);
            continue;
        }
#endif
        memset(&capabilities, 0, sizeof(capabilities));
        capabilities.cb_size = RDP_USB_REDIRECTION_DEVICE_CAPABILITIES_SIZE;
        capabilities.usb_bus_interface_version = 2;
        capabilities.usbdi_version = 0x00000600u;
        capabilities.supported_usb_version = 0x00000200u;
        capabilities.device_is_high_speed = 1;

#ifdef RDP_HAVE_LIBUSB
        if (have_backend_device)
            status = rdp_session_usb_build_descriptor_device_strings(&backend_device.descriptor,
                                                                     i,
                                                                     &instance,
                                                                     &hardware,
                                                                     &compatibility,
                                                                     &container);
        else
#endif
            status = rdp_session_usb_build_device_strings(selector,
                                                          i,
                                                          &instance,
                                                          &hardware,
                                                          &compatibility,
                                                          &container);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_usb_redirection_write_add_device(&packet,
                                                          rdp_session_usb_next_message_id(session),
                                                          interface_id,
                                                          instance.data,
                                                          (uint32_t)instance.length,
                                                          hardware.data,
                                                          (uint32_t)hardware.length,
                                                          compatibility.data,
                                                          (uint32_t)compatibility.length,
                                                          container.data,
                                                          (uint32_t)container.length,
                                                          &capabilities);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_usb_redirection_packet(session,
                                                             &packet,
                                                             "client.urbdrc.add_device");
        if (status == LIBRDP_STATUS_OK)
        {
            session->usb_device_count_sent++;
#ifdef RDP_HAVE_LIBUSB
            backend_name = have_backend_device && backend_device.handle ? "libusb" : "descriptor";
#endif
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.urbdrc.add_device",
                            "dvc_channel_id=%u selector=\"%s\" interface_id=%u count=%u backend=%s",
                            session->usb_redirection_channel_id,
                            selector ? selector : "",
                            interface_id,
                            session->usb_device_count_sent,
#ifdef RDP_HAVE_LIBUSB
                            backend_name
#else
                            "synthetic"
#endif
            );
        }
        rdp_buffer_free(&container);
        rdp_buffer_free(&compatibility);
        rdp_buffer_free(&hardware);
        rdp_buffer_free(&instance);
        rdp_buffer_free(&packet);
    }
    return status;
}

#ifdef RDP_HAVE_LIBUSB
static const rdp_usb_backend_device* rdp_session_usb_device_by_interface(const librdp_session* session,
                                                                         uint32_t interface_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < LIBRDP_SETTINGS_MAX_USB_DEVICES; i++)
    {
        if (session->usb_devices[i].active && session->usb_devices[i].interface_id == interface_id)
            return &session->usb_devices[i];
    }
    return NULL;
}

static rdp_usb_backend_device* rdp_session_usb_device_by_interface_mut(librdp_session* session,
                                                                       uint32_t interface_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < LIBRDP_SETTINGS_MAX_USB_DEVICES; i++)
    {
        if (session->usb_devices[i].active && session->usb_devices[i].interface_id == interface_id)
            return &session->usb_devices[i];
    }
    return NULL;
}

static uint32_t rdp_session_usb_transfer_timeout(const librdp_session* session, uint32_t requested_ms)
{
    const librdp_usb_policy* policy = rdp_settings_usb_policy_internal(session ? session->settings : NULL);
    uint32_t cap = policy && policy->max_transfer_ms ? policy->max_transfer_ms : 5000u;

    if (requested_ms == 0 || requested_ms > cap)
        return cap;
    return requested_ms;
}

static uint32_t rdp_session_usb_reset_interface(librdp_session* session, uint32_t interface_id)
{
    rdp_usb_backend_device* device = rdp_session_usb_device_by_interface_mut(session, interface_id);

    return rdp_usb_backend_reset_device(device);
}

static int rdp_session_usb_read_ascii_descriptor(libusb_device_handle* handle,
                                                 uint8_t descriptor_index,
                                                 char* out,
                                                 size_t out_len)
{
    int rc = 0;

    if (!handle || descriptor_index == 0 || !out || out_len == 0)
        return 0;
    rc = libusb_get_string_descriptor_ascii(handle,
                                            descriptor_index,
                                            (unsigned char*)out,
                                            (int)out_len - 1);
    if (rc <= 0)
        return 0;
    out[rc] = '\0';
    return 1;
}

static const char* rdp_session_usb_device_text(librdp_session* session,
                                               uint32_t interface_id,
                                               uint32_t text_type,
                                               char* out,
                                               size_t out_len)
{
    rdp_usb_backend_device* device = rdp_session_usb_device_by_interface_mut(session, interface_id);
    char manufacturer[128];
    char product[128];
    char serial[128];

    if (!out || out_len == 0)
        return "";
    out[0] = '\0';
    if (!device || !device->handle)
    {
        snprintf(out, out_len, "USB redirected device");
        return out;
    }
    memset(manufacturer, 0, sizeof(manufacturer));
    memset(product, 0, sizeof(product));
    memset(serial, 0, sizeof(serial));
    (void)rdp_session_usb_read_ascii_descriptor(device->handle,
                                                device->descriptor.iManufacturer,
                                                manufacturer,
                                                sizeof(manufacturer));
    (void)rdp_session_usb_read_ascii_descriptor(device->handle,
                                                device->descriptor.iProduct,
                                                product,
                                                sizeof(product));
    (void)rdp_session_usb_read_ascii_descriptor(device->handle,
                                                device->descriptor.iSerialNumber,
                                                serial,
                                                sizeof(serial));
    if (text_type == 2u && serial[0] != '\0')
        snprintf(out, out_len, "%s", serial);
    else if (manufacturer[0] != '\0' && product[0] != '\0')
        snprintf(out, out_len, "%s %s", manufacturer, product);
    else if (product[0] != '\0')
        snprintf(out, out_len, "%s", product);
    else if (manufacturer[0] != '\0')
        snprintf(out, out_len, "%s USB device", manufacturer);
    else
        snprintf(out,
                 out_len,
                 "USB %04x:%04x",
                 (unsigned)device->descriptor.idVendor,
                 (unsigned)device->descriptor.idProduct);
    out[out_len - 1u] = '\0';
    return out;
}

#endif

typedef struct rdp_session_usb_control_transfer
{
    uint8_t endpoint;
    uint32_t transfer_flags;
    uint32_t timeout;
    uint8_t request_type;
    uint8_t request;
    uint16_t value;
    uint16_t index;
    uint32_t output_buffer_size;
    const uint8_t* data;
    uint32_t data_len;
} rdp_session_usb_control_transfer;

typedef struct rdp_session_usb_pipe_transfer
{
    uint8_t endpoint;
    uint32_t transfer_flags;
    uint32_t output_buffer_size;
    const uint8_t* data;
    uint32_t data_len;
} rdp_session_usb_pipe_transfer;

typedef struct rdp_session_usb_iso_packet
{
    uint32_t offset;
    uint32_t length;
    uint32_t status;
} rdp_session_usb_iso_packet;

typedef struct rdp_session_usb_iso_transfer
{
    uint8_t endpoint;
    uint32_t transfer_flags;
    uint32_t start_frame;
    uint32_t packet_count;
    uint32_t error_count;
    uint32_t output_buffer_size;
    const uint8_t* data;
    uint32_t data_len;
    rdp_session_usb_iso_packet packets[256];
} rdp_session_usb_iso_transfer;

typedef struct rdp_session_usb_os_feature_request
{
    uint8_t recipient;
    uint8_t interface_number;
    uint8_t page_index;
    uint16_t feature_index;
    uint32_t output_buffer_size;
    const uint8_t* data;
    uint32_t data_len;
} rdp_session_usb_os_feature_request;

#ifdef RDP_HAVE_LIBUSB
static uint16_t rdp_session_usb_read_u16_le_unaligned(const uint8_t* data)
{
    if (!data)
        return 0;
    return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8u));
}

static librdp_status rdp_session_usb_parse_control_transfer(
    const rdp_usb_redirection_transfer* transfer,
    rdp_session_usb_control_transfer* parsed)
{
    const uint8_t* input = NULL;
    size_t length = 0;
    size_t offset = RDP_SESSION_USB_URB_HEADER_LENGTH;
    uint32_t pipe_handle = 0;
    uint16_t setup_length = 0;

    if (!transfer || !parsed || !transfer->ts_urb)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(parsed, 0, sizeof(*parsed));
    input = transfer->ts_urb;
    length = transfer->cb_ts_urb;
    if (length < offset + 20u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    pipe_handle = rdp_session_read_u32_le_unaligned(input + offset);
    parsed->endpoint = (uint8_t)(pipe_handle & 0xffu);
    offset += 4u;
    parsed->transfer_flags = rdp_session_read_u32_le_unaligned(input + offset);
    offset += 4u;
    parsed->timeout = 2000u;
    if (transfer->urb.function == RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER_EX)
    {
        if (length < offset + 4u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        parsed->timeout = rdp_session_read_u32_le_unaligned(input + offset);
        offset += 4u;
    }
    if (length < offset + 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed->request_type = input[offset];
    parsed->request = input[offset + 1u];
    parsed->value = rdp_session_usb_read_u16_le_unaligned(input + offset + 2u);
    parsed->index = rdp_session_usb_read_u16_le_unaligned(input + offset + 4u);
    setup_length = rdp_session_usb_read_u16_le_unaligned(input + offset + 6u);
    parsed->output_buffer_size = rdp_session_read_u32_le_unaligned(input + offset + 8u);
    offset += 12u;
    if (setup_length != parsed->output_buffer_size ||
        parsed->output_buffer_size > RDP_SESSION_MAX_FILE_IO_BYTES ||
        parsed->output_buffer_size > UINT16_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (transfer->header.function_id == RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST)
    {
        if (transfer->output_buffer_len > 0)
        {
            parsed->data = transfer->output_buffer;
            parsed->data_len = transfer->output_buffer_len;
        }
        else
        {
            if (parsed->output_buffer_size > length - offset)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            parsed->data = input + offset;
            parsed->data_len = parsed->output_buffer_size;
        }
        if (parsed->data_len != parsed->output_buffer_size)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_usb_parse_pipe_transfer(
    const rdp_usb_redirection_transfer* transfer,
    rdp_session_usb_pipe_transfer* parsed)
{
    const uint8_t* input = NULL;
    size_t length = 0;
    size_t offset = RDP_SESSION_USB_URB_HEADER_LENGTH;
    uint32_t pipe_handle = 0;

    if (!transfer || !parsed || !transfer->ts_urb)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(parsed, 0, sizeof(*parsed));
    input = transfer->ts_urb;
    length = transfer->cb_ts_urb;
    if (length < offset + 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    pipe_handle = rdp_session_read_u32_le_unaligned(input + offset);
    parsed->endpoint = (uint8_t)(pipe_handle & 0xffu);
    offset += 4u;
    parsed->transfer_flags = rdp_session_read_u32_le_unaligned(input + offset);
    offset += 4u;
    parsed->output_buffer_size = rdp_session_read_u32_le_unaligned(input + offset);
    offset += 4u;
    if (parsed->output_buffer_size > RDP_SESSION_MAX_FILE_IO_BYTES ||
        parsed->output_buffer_size > INT_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (transfer->header.function_id == RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST)
    {
        if (transfer->output_buffer_len > 0)
        {
            parsed->data = transfer->output_buffer;
            parsed->data_len = transfer->output_buffer_len;
        }
        else
        {
            if (parsed->output_buffer_size > length - offset)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            parsed->data = input + offset;
            parsed->data_len = parsed->output_buffer_size;
        }
        if (parsed->data_len != parsed->output_buffer_size)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_usb_parse_iso_transfer(const rdp_usb_redirection_transfer* transfer,
                                                        rdp_session_usb_iso_transfer* parsed)
{
    const uint8_t* input = NULL;
    size_t length = 0;
    size_t offset = RDP_SESSION_USB_URB_HEADER_LENGTH;
    uint32_t pipe_handle = 0;
    uint64_t descriptor_bytes = 0;

    if (!transfer || !parsed || !transfer->ts_urb)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(parsed, 0, sizeof(*parsed));
    input = transfer->ts_urb;
    length = transfer->cb_ts_urb;
    if (length < offset + 24u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    pipe_handle = rdp_session_read_u32_le_unaligned(input + offset);
    parsed->endpoint = (uint8_t)(pipe_handle & 0xffu);
    offset += 4u;
    parsed->transfer_flags = rdp_session_read_u32_le_unaligned(input + offset);
    offset += 4u;
    parsed->start_frame = rdp_session_read_u32_le_unaligned(input + offset);
    offset += 4u;
    parsed->packet_count = rdp_session_read_u32_le_unaligned(input + offset);
    offset += 4u;
    parsed->error_count = rdp_session_read_u32_le_unaligned(input + offset);
    offset += 4u;
    if (parsed->packet_count == 0 || parsed->packet_count > 256u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    descriptor_bytes = (uint64_t)parsed->packet_count * 12ull;
    if (descriptor_bytes > SIZE_MAX || length - offset < (size_t)descriptor_bytes + 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (uint32_t i = 0; i < parsed->packet_count; i++)
    {
        parsed->packets[i].offset = rdp_session_read_u32_le_unaligned(input + offset);
        parsed->packets[i].length = rdp_session_read_u32_le_unaligned(input + offset + 4u);
        parsed->packets[i].status = rdp_session_read_u32_le_unaligned(input + offset + 8u);
        offset += 12u;
        if (parsed->packets[i].length > RDP_SESSION_MAX_FILE_IO_BYTES ||
            parsed->packets[i].offset > RDP_SESSION_MAX_FILE_IO_BYTES ||
            parsed->packets[i].length > RDP_SESSION_MAX_FILE_IO_BYTES - parsed->packets[i].offset)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    parsed->output_buffer_size = rdp_session_read_u32_le_unaligned(input + offset);
    offset += 4u;
    if (parsed->output_buffer_size > RDP_SESSION_MAX_FILE_IO_BYTES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (uint32_t i = 0; i < parsed->packet_count; i++)
    {
        if (parsed->packets[i].offset > parsed->output_buffer_size ||
            parsed->packets[i].length > parsed->output_buffer_size - parsed->packets[i].offset)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (transfer->header.function_id == RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST)
    {
        if (transfer->output_buffer_len > 0)
        {
            parsed->data = transfer->output_buffer;
            parsed->data_len = transfer->output_buffer_len;
        }
        else
        {
            if (parsed->output_buffer_size > length - offset)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            parsed->data = input + offset;
            parsed->data_len = parsed->output_buffer_size;
        }
        if (parsed->data_len != parsed->output_buffer_size)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_usb_parse_os_feature_request(
    const rdp_usb_redirection_transfer* transfer,
    rdp_session_usb_os_feature_request* parsed)
{
    const uint8_t* input = NULL;
    size_t length = 0;
    size_t offset = RDP_SESSION_USB_URB_HEADER_LENGTH;

    if (!transfer || !parsed || !transfer->ts_urb)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(parsed, 0, sizeof(*parsed));
    input = transfer->ts_urb;
    length = transfer->cb_ts_urb;
    if (length < offset + 12u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    parsed->recipient = input[offset] & 0x1fu;
    parsed->interface_number = input[offset + 1u];
    parsed->page_index = input[offset + 2u];
    parsed->feature_index = rdp_session_usb_read_u16_le_unaligned(input + offset + 3u);
    parsed->output_buffer_size = rdp_session_read_u32_le_unaligned(input + offset + 8u);
    offset += 12u;
    if (parsed->output_buffer_size > RDP_SESSION_MAX_FILE_IO_BYTES)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (transfer->header.function_id == RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST)
    {
        if (transfer->output_buffer_len > 0)
        {
            parsed->data = transfer->output_buffer;
            parsed->data_len = transfer->output_buffer_len;
        }
        else
        {
            if (parsed->output_buffer_size > length - offset)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            parsed->data = input + offset;
            parsed->data_len = parsed->output_buffer_size;
        }
        if (parsed->data_len != parsed->output_buffer_size)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return LIBRDP_STATUS_OK;
}
#endif

static uint32_t rdp_session_usb_port_status(const librdp_session* session, uint32_t interface_id)
{
#ifdef RDP_HAVE_LIBUSB
    const rdp_usb_backend_device* device = rdp_session_usb_device_by_interface(session, interface_id);

    if (device)
    {
        if (device->descriptor.bcdUSB < 0x0110u)
            return 0x00000303u;
        if (device->descriptor.bcdUSB < 0x0200u)
            return 0x00000103u;
    }
#else
    (void)session;
    (void)interface_id;
#endif
    return 0x00000503u;
}

static uint32_t rdp_session_usb_bus_time(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint32_t)(((uint64_t)ts.tv_sec * 1000ull) + ((uint64_t)ts.tv_nsec / 1000000ull));
}

static librdp_status rdp_session_usb_make_u32_output(uint32_t value, rdp_buffer* output)
{
    if (!output)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append_u32_le(output, value);
}

static librdp_status rdp_session_usb_make_urb_result_payload(uint32_t usbd_status,
                                                             const uint8_t* payload,
                                                             uint32_t payload_len,
                                                             rdp_buffer* result)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!result || (!payload && payload_len > 0) || payload_len > UINT16_MAX - 8u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(result, (uint16_t)(8u + payload_len));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(result, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(result, usbd_status);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(result, payload, payload_len);
    return status;
}

static librdp_status rdp_session_usb_make_urb_result(uint32_t usbd_status, rdp_buffer* result)
{
    return rdp_session_usb_make_urb_result_payload(usbd_status, NULL, 0, result);
}

static librdp_status rdp_session_usb_send_io_completion(librdp_session* session,
                                                        uint32_t request_id,
                                                        uint32_t hresult,
                                                        uint32_t information,
                                                        const uint8_t* output,
                                                        uint32_t output_len,
                                                        const char* event)
{
    rdp_usb_redirection_io_completion completion;
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!output && output_len > 0) || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!session->usb_request_completion_ready)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.completion.skipped",
                        "request_id=%u reason=no_callback",
                        request_id);
        return LIBRDP_STATUS_OK;
    }
    memset(&completion, 0, sizeof(completion));
    completion.request_id = request_id;
    completion.hresult = hresult;
    completion.information = information;
    completion.output_buffer = output;
    completion.output_buffer_len = output_len;
    rdp_buffer_init(&packet);
    status = rdp_usb_redirection_write_io_control_completion(&packet,
                                                             session->usb_request_completion_interface_id,
                                                             rdp_session_usb_next_message_id(session),
                                                             &completion);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_usb_redirection_packet(session, &packet, event);
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status rdp_session_usb_send_urb_completion_payload(librdp_session* session,
                                                                 const rdp_usb_redirection_transfer* transfer,
                                                                 uint32_t usbd_status,
                                                                 const uint8_t* result_payload,
                                                                 uint32_t result_payload_len,
                                                                 const uint8_t* output,
                                                                 uint32_t output_len,
                                                                 const char* event)
{
    rdp_usb_redirection_urb_completion completion;
    rdp_buffer packet;
    rdp_buffer result;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !transfer || !event || (!result_payload && result_payload_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (transfer->urb.no_ack)
        return LIBRDP_STATUS_OK;
    if (!session->usb_request_completion_ready)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.urb_completion.skipped",
                        "request_id=%u reason=no_callback",
                        transfer->urb.request_id);
        return LIBRDP_STATUS_OK;
    }
    memset(&completion, 0, sizeof(completion));
    completion.request_id = transfer->urb.request_id;
    completion.hresult = RDP_SESSION_HRESULT_OK;
    completion.output_buffer = output;
    completion.output_buffer_len = output_len;
    rdp_buffer_init(&result);
    rdp_buffer_init(&packet);
    status = rdp_session_usb_make_urb_result_payload(usbd_status,
                                                     result_payload,
                                                     result_payload_len,
                                                     &result);
    if (status == LIBRDP_STATUS_OK)
    {
        completion.ts_urb_result = result.data;
        completion.cb_ts_urb_result = (uint32_t)result.length;
        if (output_len > 0)
            status = rdp_usb_redirection_write_urb_completion(&packet,
                                                              session->usb_request_completion_interface_id,
                                                              rdp_session_usb_next_message_id(session),
                                                              &completion);
        else
            status = rdp_usb_redirection_write_urb_completion_no_data(
                &packet,
                session->usb_request_completion_interface_id,
                rdp_session_usb_next_message_id(session),
                &completion);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_usb_redirection_packet(session, &packet, event);
    rdp_buffer_free(&packet);
    rdp_buffer_free(&result);
    return status;
}

#ifdef RDP_HAVE_LIBUSB
static uint32_t rdp_session_usb_append_interface_result(
    rdp_buffer* result,
    libusb_device_handle* handle,
    uint8_t interface_number,
    uint8_t alternate_setting)
{
    libusb_device* usb_device = NULL;
    struct libusb_config_descriptor* config = NULL;
    const struct libusb_interface_descriptor* selected = NULL;
    int rc = 0;

    if (!result || !handle)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    usb_device = libusb_get_device(handle);
    rc = libusb_get_active_config_descriptor(usb_device, &config);
    if (rc != LIBUSB_SUCCESS)
        return rdp_usb_backend_libusb_status(rc);
    for (uint8_t i = 0; i < config->bNumInterfaces && !selected; i++)
    {
        const struct libusb_interface* iface = &config->interface[i];

        for (int j = 0; j < iface->num_altsetting; j++)
        {
            const struct libusb_interface_descriptor* alt = &iface->altsetting[j];

            if (alt->bInterfaceNumber == interface_number &&
                alt->bAlternateSetting == alternate_setting)
            {
                selected = alt;
                break;
            }
        }
    }
    if (!selected)
    {
        libusb_free_config_descriptor(config);
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    }
    if (rdp_buffer_append_u16_le(result,
                                 (uint16_t)(16u + ((uint32_t)selected->bNumEndpoints * 20u))) !=
            LIBRDP_STATUS_OK ||
        rdp_buffer_append_u8(result, selected->bInterfaceNumber) != LIBRDP_STATUS_OK ||
        rdp_buffer_append_u8(result, selected->bAlternateSetting) != LIBRDP_STATUS_OK ||
        rdp_buffer_append_u8(result, selected->bInterfaceClass) != LIBRDP_STATUS_OK ||
        rdp_buffer_append_u8(result, selected->bInterfaceSubClass) != LIBRDP_STATUS_OK ||
        rdp_buffer_append_u8(result, selected->bInterfaceProtocol) != LIBRDP_STATUS_OK ||
        rdp_buffer_append_u8(result, 0) != LIBRDP_STATUS_OK ||
        rdp_buffer_append_u32_le(result, selected->bInterfaceNumber) != LIBRDP_STATUS_OK ||
        rdp_buffer_append_u32_le(result, selected->bNumEndpoints) != LIBRDP_STATUS_OK)
    {
        libusb_free_config_descriptor(config);
        return RDP_USB_REDIRECTION_USBD_STATUS_NO_MEMORY;
    }
    for (uint8_t i = 0; i < selected->bNumEndpoints; i++)
    {
        const struct libusb_endpoint_descriptor* ep = &selected->endpoint[i];
        uint32_t transfer_type = (uint32_t)(ep->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK);

        if (rdp_buffer_append_u16_le(result, ep->wMaxPacketSize) != LIBRDP_STATUS_OK ||
            rdp_buffer_append_u8(result, ep->bEndpointAddress) != LIBRDP_STATUS_OK ||
            rdp_buffer_append_u8(result, ep->bInterval) != LIBRDP_STATUS_OK ||
            rdp_buffer_append_u32_le(result, transfer_type) != LIBRDP_STATUS_OK ||
            rdp_buffer_append_u32_le(result, ep->bEndpointAddress) != LIBRDP_STATUS_OK ||
            rdp_buffer_append_u32_le(result, 64u * 1024u) != LIBRDP_STATUS_OK ||
            rdp_buffer_append_u32_le(result, 0) != LIBRDP_STATUS_OK)
        {
            libusb_free_config_descriptor(config);
            return RDP_USB_REDIRECTION_USBD_STATUS_NO_MEMORY;
        }
    }
    libusb_free_config_descriptor(config);
    return RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
}

static uint32_t rdp_session_usb_parse_ms_interface(const uint8_t* data,
                                                   size_t length,
                                                   size_t* offset,
                                                   uint8_t* interface_number,
                                                   uint8_t* alternate_setting)
{
    uint32_t pipe_count = 0;

    if (!data || !offset || !interface_number || !alternate_setting || *offset > length ||
        length - *offset < 12u)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    *interface_number = data[*offset + 4u];
    *alternate_setting = data[*offset + 5u];
    pipe_count = rdp_session_read_u32_le_unaligned(data + *offset + 8u);
    if (pipe_count > (length - *offset - 12u) / 12u)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    *offset += 12u + ((size_t)pipe_count * 12u);
    return RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
}

static uint32_t rdp_session_usb_control_request(librdp_session* session,
                                                libusb_device_handle* handle,
                                                uint8_t request_type,
                                                uint8_t request,
                                                uint16_t value,
                                                uint16_t index,
                                                uint32_t timeout,
                                                const uint8_t* input,
                                                uint32_t input_len,
                                                uint32_t output_buffer_size,
                                                uint8_t** output,
                                                uint32_t* output_len)
{
    uint8_t* buffer = NULL;
    uint32_t actual = 0;
    uint32_t capped_timeout = rdp_session_usb_transfer_timeout(session, timeout);

    if (!session || !session->usb_libusb || !handle || (!input && input_len > 0) || !output || !output_len ||
        output_buffer_size > UINT16_MAX)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    *output = NULL;
    *output_len = 0;
    if (output_buffer_size > 0)
    {
        buffer = (uint8_t*)calloc(1, output_buffer_size);
        if (!buffer)
            return RDP_USB_REDIRECTION_USBD_STATUS_NO_MEMORY;
        if ((request_type & LIBUSB_ENDPOINT_IN) == 0 && input_len > 0)
        {
            if (input_len != output_buffer_size)
            {
                free(buffer);
                return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
            }
            memcpy(buffer, input, input_len);
        }
    }
    {
        uint32_t usbd_status = rdp_usb_backend_control_transfer(session->usb_libusb,
                                                               handle,
                                                               request_type,
                                                               request,
                                                               value,
                                                               index,
                                                               buffer,
                                                               output_buffer_size,
                                                               capped_timeout,
                                                               &actual);

        if (usbd_status != RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
        {
            free(buffer);
            return usbd_status;
        }
    }
    if ((request_type & LIBUSB_ENDPOINT_IN) != 0 && actual > 0)
    {
        *output = buffer;
        *output_len = (uint32_t)actual;
    }
    else
    {
        free(buffer);
    }
    return RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
}

static uint32_t rdp_session_usb_complete_select_configuration(librdp_session* session,
                                                              rdp_usb_backend_device* device,
                                                              const rdp_usb_redirection_transfer* transfer,
                                                              rdp_buffer* result_payload)
{
    const uint8_t* data = NULL;
    size_t length = 0;
    size_t offset = RDP_SESSION_USB_URB_HEADER_LENGTH;
    uint8_t valid = 0;
    uint32_t interface_count = 0;
    uint8_t interfaces[32];
    uint8_t alternates[32];
    uint8_t configuration_value = 0;
    uint32_t usbd_status = RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;

    if (!session || !device || !transfer || !result_payload || !transfer->ts_urb ||
        transfer->header.function_id != RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    data = transfer->ts_urb;
    length = transfer->cb_ts_urb;
    if (length < offset + 8u)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    valid = data[offset];
    interface_count = rdp_session_read_u32_le_unaligned(data + offset + 4u);
    offset += 8u;
    if (interface_count > sizeof(interfaces))
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    if (!valid)
    {
        if (rdp_buffer_append_u32_le(result_payload, 0) != LIBRDP_STATUS_OK ||
            rdp_buffer_append_u32_le(result_payload, 0) != LIBRDP_STATUS_OK)
            return RDP_USB_REDIRECTION_USBD_STATUS_NO_MEMORY;
        return RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
    }
    for (uint32_t i = 0; i < interface_count; i++)
    {
        usbd_status = rdp_session_usb_parse_ms_interface(data,
                                                         length,
                                                         &offset,
                                                         &interfaces[i],
                                                         &alternates[i]);
        if (usbd_status != RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
            return usbd_status;
    }
    if (length - offset < 6u || data[offset] != 9u || data[offset + 1u] != 2u)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    configuration_value = data[offset + 5u];
    {
        int rc = libusb_set_configuration(device->handle, configuration_value);

        if (rc != LIBUSB_SUCCESS && rc != LIBUSB_ERROR_BUSY)
            return rdp_usb_backend_libusb_status(rc);
    }
    if (rdp_buffer_append_u32_le(result_payload, configuration_value) != LIBRDP_STATUS_OK ||
        rdp_buffer_append_u32_le(result_payload, interface_count) != LIBRDP_STATUS_OK)
        return RDP_USB_REDIRECTION_USBD_STATUS_NO_MEMORY;
    for (uint32_t i = 0; i < interface_count; i++)
    {
        usbd_status = rdp_usb_backend_select_interface(device, interfaces[i], alternates[i]);
        if (usbd_status != RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
            return usbd_status;
        usbd_status = rdp_session_usb_append_interface_result(result_payload,
                                                              device->handle,
                                                              interfaces[i],
                                                              alternates[i]);
        if (usbd_status != RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
            return usbd_status;
    }
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.urbdrc.select_configuration",
                    "interface_id=%u configuration=%u interfaces=%u status=%u",
                    transfer->header.interface_id,
                    configuration_value,
                    interface_count,
                    usbd_status);
    return usbd_status;
}

static uint32_t rdp_session_usb_complete_select_interface(rdp_usb_backend_device* device,
                                                          const rdp_usb_redirection_transfer* transfer,
                                                          rdp_buffer* result_payload)
{
    const uint8_t* data = NULL;
    size_t length = 0;
    size_t offset = RDP_SESSION_USB_URB_HEADER_LENGTH + 4u;
    uint8_t interface_number = 0;
    uint8_t alternate_setting = 0;
    uint32_t output_size = 0;
    uint32_t usbd_status = RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;

    if (!device || !transfer || !result_payload || !transfer->ts_urb ||
        transfer->header.function_id != RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    data = transfer->ts_urb;
    length = transfer->cb_ts_urb;
    usbd_status = rdp_session_usb_parse_ms_interface(data,
                                                     length,
                                                     &offset,
                                                     &interface_number,
                                                     &alternate_setting);
    if (usbd_status != RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
        return usbd_status;
    if (length - offset < 4u)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    output_size = rdp_session_read_u32_le_unaligned(data + offset);
    if (output_size != 0)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    usbd_status = rdp_usb_backend_select_interface(device, interface_number, alternate_setting);
    if (usbd_status != RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
        return usbd_status;
    return rdp_session_usb_append_interface_result(result_payload,
                                                   device->handle,
                                                   interface_number,
                                                   alternate_setting);
}

static uint32_t rdp_session_usb_complete_descriptor_request(librdp_session* session,
                                                            rdp_usb_backend_device* device,
                                                            const rdp_usb_redirection_transfer* transfer,
                                                            uint8_t recipient,
                                                            uint8_t get_request,
                                                            uint8_t** output,
                                                            uint32_t* output_len)
{
    const uint8_t* data = NULL;
    size_t length = 0;
    size_t offset = RDP_SESSION_USB_URB_HEADER_LENGTH;
    uint8_t descriptor_index = 0;
    uint8_t descriptor_type = 0;
    uint16_t language_id = 0;
    uint32_t output_buffer_size = 0;
    const uint8_t* input = NULL;
    uint32_t input_len = 0;
    uint8_t request_type = recipient;

    if (!device || !transfer || !transfer->ts_urb || !output || !output_len)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    data = transfer->ts_urb;
    length = transfer->cb_ts_urb;
    if (length < offset + 8u)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    descriptor_index = data[offset];
    descriptor_type = data[offset + 1u];
    language_id = rdp_session_usb_read_u16_le_unaligned(data + offset + 2u);
    output_buffer_size = rdp_session_read_u32_le_unaligned(data + offset + 4u);
    offset += 8u;
    if (output_buffer_size > RDP_SESSION_MAX_FILE_IO_BYTES)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    if (get_request)
        request_type |= LIBUSB_ENDPOINT_IN;
    else
    {
        if (output_buffer_size > length - offset)
            return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
        input = data + offset;
        input_len = output_buffer_size;
    }
    return rdp_session_usb_control_request(session,
                                           device->handle,
                                           request_type,
                                           get_request ? 0x06u : 0x07u,
                                           (uint16_t)(((uint16_t)descriptor_type << 8u) | descriptor_index),
                                           language_id,
                                           1000u,
                                           input,
                                           input_len,
                                           output_buffer_size,
                                           output,
                                           output_len);
}

static uint32_t rdp_session_usb_complete_feature_request(librdp_session* session,
                                                         rdp_usb_backend_device* device,
                                                         const rdp_usb_redirection_transfer* transfer,
                                                         uint8_t recipient,
                                                         uint8_t set_feature,
                                                         uint8_t** output,
                                                         uint32_t* output_len)
{
    const uint8_t* data = NULL;
    size_t length = 0;
    size_t offset = RDP_SESSION_USB_URB_HEADER_LENGTH;
    uint16_t feature_selector = 0;
    uint16_t index = 0;
    uint32_t output_buffer_size = 0;
    const uint8_t* input = NULL;
    uint32_t input_len = 0;
    uint8_t request_type = recipient;

    if (!device || !transfer || !transfer->ts_urb || !output || !output_len)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    data = transfer->ts_urb;
    length = transfer->cb_ts_urb;
    if (length < offset + 8u)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    feature_selector = rdp_session_usb_read_u16_le_unaligned(data + offset);
    index = rdp_session_usb_read_u16_le_unaligned(data + offset + 2u);
    output_buffer_size = rdp_session_read_u32_le_unaligned(data + offset + 4u);
    offset += 8u;
    if (output_buffer_size > RDP_SESSION_MAX_FILE_IO_BYTES)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    if (transfer->header.function_id == RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST)
        request_type |= LIBUSB_ENDPOINT_IN;
    else
    {
        if (output_buffer_size > length - offset)
            return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
        input = data + offset;
        input_len = output_buffer_size;
    }
    return rdp_session_usb_control_request(session,
                                           device->handle,
                                           request_type,
                                           set_feature ? 0x03u : 0x01u,
                                           feature_selector,
                                           index,
                                           1000u,
                                           input,
                                           input_len,
                                           output_buffer_size,
                                           output,
                                           output_len);
}

static uint32_t rdp_session_usb_complete_get_status_request(librdp_session* session,
                                                            rdp_usb_backend_device* device,
                                                            const rdp_usb_redirection_transfer* transfer,
                                                            uint8_t recipient,
                                                            uint8_t** output,
                                                            uint32_t* output_len)
{
    const uint8_t* data = NULL;
    size_t offset = RDP_SESSION_USB_URB_HEADER_LENGTH;
    uint16_t index = 0;
    uint32_t output_buffer_size = 0;

    if (!device || !transfer || !transfer->ts_urb || !output || !output_len ||
        transfer->header.function_id != RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST ||
        transfer->cb_ts_urb < offset + 8u)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    data = transfer->ts_urb;
    index = rdp_session_usb_read_u16_le_unaligned(data + offset);
    output_buffer_size = rdp_session_read_u32_le_unaligned(data + offset + 4u);
    if (output_buffer_size > RDP_SESSION_MAX_FILE_IO_BYTES)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    return rdp_session_usb_control_request(session,
                                           device->handle,
                                           (uint8_t)(LIBUSB_ENDPOINT_IN | recipient),
                                           0x00u,
                                           0,
                                           index,
                                           1000u,
                                           NULL,
                                           0,
                                           output_buffer_size,
                                           output,
                                           output_len);
}

static uint32_t rdp_session_usb_complete_vendor_class_request(librdp_session* session,
                                                              rdp_usb_backend_device* device,
                                                              const rdp_usb_redirection_transfer* transfer,
                                                              uint8_t type,
                                                              uint8_t recipient,
                                                              uint8_t** output,
                                                              uint32_t* output_len)
{
    const uint8_t* data = NULL;
    size_t length = 0;
    size_t offset = RDP_SESSION_USB_URB_HEADER_LENGTH;
    uint32_t transfer_flags = 0;
    uint8_t request = 0;
    uint16_t value = 0;
    uint16_t index = 0;
    uint32_t output_buffer_size = 0;
    uint8_t request_type = (uint8_t)(type | recipient);
    const uint8_t* input = NULL;
    uint32_t input_len = 0;

    if (!device || !transfer || !transfer->ts_urb || !output || !output_len)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    data = transfer->ts_urb;
    length = transfer->cb_ts_urb;
    if (length < offset + 16u)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    transfer_flags = rdp_session_read_u32_le_unaligned(data + offset);
    request = data[offset + 5u];
    value = rdp_session_usb_read_u16_le_unaligned(data + offset + 6u);
    index = rdp_session_usb_read_u16_le_unaligned(data + offset + 8u);
    output_buffer_size = rdp_session_read_u32_le_unaligned(data + offset + 12u);
    offset += 16u;
    if (output_buffer_size > RDP_SESSION_MAX_FILE_IO_BYTES)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    if ((transfer_flags & RDP_USB_REDIRECTION_TRANSFER_DIRECTION) != 0)
        request_type |= LIBUSB_ENDPOINT_IN;
    else
    {
        if (output_buffer_size > length - offset)
            return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
        input = data + offset;
        input_len = output_buffer_size;
    }
    return rdp_session_usb_control_request(session,
                                           device->handle,
                                           request_type,
                                           request,
                                           value,
                                           index,
                                           2000u,
                                           input,
                                           input_len,
                                           output_buffer_size,
                                           output,
                                           output_len);
}

static uint32_t rdp_session_usb_complete_get_configuration_request(librdp_session* session,
                                                                   rdp_usb_backend_device* device,
                                                                   const rdp_usb_redirection_transfer* transfer,
                                                                   uint8_t** output,
                                                                   uint32_t* output_len)
{
    const uint8_t* data = NULL;
    size_t offset = RDP_SESSION_USB_URB_HEADER_LENGTH;
    uint32_t output_buffer_size = 0;

    if (!device || !transfer || !transfer->ts_urb || !output || !output_len ||
        transfer->header.function_id != RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST ||
        transfer->cb_ts_urb < offset + 4u)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    data = transfer->ts_urb;
    output_buffer_size = rdp_session_read_u32_le_unaligned(data + offset);
    if (output_buffer_size > RDP_SESSION_MAX_FILE_IO_BYTES)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    return rdp_session_usb_control_request(session,
                                           device->handle,
                                           (uint8_t)(LIBUSB_ENDPOINT_IN | 0x00u),
                                           0x08u,
                                           0,
                                           0,
                                           1000u,
                                           NULL,
                                           0,
                                           output_buffer_size,
                                           output,
                                           output_len);
}

static uint32_t rdp_session_usb_complete_get_interface_request(librdp_session* session,
                                                               rdp_usb_backend_device* device,
                                                               const rdp_usb_redirection_transfer* transfer,
                                                               uint8_t** output,
                                                               uint32_t* output_len)
{
    const uint8_t* data = NULL;
    size_t offset = RDP_SESSION_USB_URB_HEADER_LENGTH;
    uint16_t interface_number = 0;
    uint32_t output_buffer_size = 0;

    if (!device || !transfer || !transfer->ts_urb || !output || !output_len ||
        transfer->header.function_id != RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST ||
        transfer->cb_ts_urb < offset + 8u)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    data = transfer->ts_urb;
    interface_number = rdp_session_usb_read_u16_le_unaligned(data + offset);
    output_buffer_size = rdp_session_read_u32_le_unaligned(data + offset + 4u);
    if (output_buffer_size > RDP_SESSION_MAX_FILE_IO_BYTES)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    return rdp_session_usb_control_request(session,
                                           device->handle,
                                           (uint8_t)(LIBUSB_ENDPOINT_IN | 0x01u),
                                           0x0au,
                                           0,
                                           interface_number,
                                           1000u,
                                           NULL,
                                           0,
                                           output_buffer_size,
                                           output,
                                           output_len);
}

static uint32_t rdp_session_usb_complete_pipe_request(rdp_usb_backend_device* device,
                                                      const rdp_usb_redirection_transfer* transfer,
                                                      uint8_t reset_pipe)
{
    const uint8_t* data = NULL;
    size_t offset = RDP_SESSION_USB_URB_HEADER_LENGTH;
    uint32_t pipe_handle = 0;
    uint32_t output_buffer_size = 0;
    int rc = 0;

    if (!device || !transfer || !transfer->ts_urb ||
        transfer->header.function_id != RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST ||
        transfer->cb_ts_urb < offset + 8u)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    data = transfer->ts_urb;
    pipe_handle = rdp_session_read_u32_le_unaligned(data + offset);
    output_buffer_size = rdp_session_read_u32_le_unaligned(data + offset + 4u);
    if (output_buffer_size != 0)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    if (!reset_pipe)
        return RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
    rc = libusb_clear_halt(device->handle, (unsigned char)(pipe_handle & 0xffu));
    return rc == LIBUSB_SUCCESS ? RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS :
                                  rdp_usb_backend_libusb_status(rc);
}

/*
 * Complete an isochronous USB transfer response. Per-packet statuses, payload
 * offsets, and backend transfer ownership are normalized before the URBDRC
 * completion is sent.
 */
static uint32_t rdp_session_usb_complete_iso_transfer(librdp_session* session,
                                                      rdp_usb_backend_device* device,
                                                      const rdp_usb_redirection_transfer* transfer,
                                                      rdp_buffer* result_payload,
                                                      uint8_t** output,
                                                      uint32_t* output_len)
{
    rdp_session_usb_iso_transfer parsed;
    rdp_usb_backend_iso_packet packets[256];
    uint8_t* buffer = NULL;
    uint32_t usbd_status = RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
    uint32_t error_count = 0;
    uint32_t actual_total = 0;
    uint32_t payload_offset = 0;
    uint8_t endpoint = 0;
    uint32_t timeout = 2000u;

    if (!session || !device || !transfer || !result_payload || !output || !output_len)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    *output = NULL;
    *output_len = 0;
    if (rdp_session_usb_parse_iso_transfer(transfer, &parsed) != LIBRDP_STATUS_OK)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    endpoint = parsed.endpoint;
    if (transfer->header.function_id == RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST)
        endpoint |= LIBUSB_ENDPOINT_IN;
    else
        endpoint &= (uint8_t)~LIBUSB_ENDPOINT_IN;
    {
        uint8_t transfer_type = LIBUSB_TRANSFER_TYPE_ISOCHRONOUS;

        usbd_status = rdp_usb_backend_claim_endpoint(device, endpoint, &transfer_type);
        if (usbd_status == RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS &&
            transfer_type != LIBUSB_TRANSFER_TYPE_ISOCHRONOUS)
            usbd_status = RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    }
    if (usbd_status != RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
        return usbd_status;
    if (parsed.output_buffer_size > 0)
    {
        buffer = (uint8_t*)calloc(1, parsed.output_buffer_size);
        if (!buffer)
            return RDP_USB_REDIRECTION_USBD_STATUS_NO_MEMORY;
        if (transfer->header.function_id == RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST)
            memcpy(buffer, parsed.data, parsed.data_len);
    }
    for (uint32_t i = 0; i < parsed.packet_count; i++)
    {
        packets[i].length = parsed.packets[i].length;
        packets[i].actual_length = 0;
        packets[i].status = RDP_USB_REDIRECTION_USBD_STATUS_DEV_NOT_RESPONDING;
    }
    timeout = rdp_session_usb_transfer_timeout(session, timeout);
    usbd_status = rdp_usb_backend_iso_transfer(session->usb_libusb,
                                               device->handle,
                                               endpoint,
                                               buffer,
                                               parsed.output_buffer_size,
                                               packets,
                                               parsed.packet_count,
                                               timeout,
                                               &actual_total);
    if (rdp_buffer_append_u32_le(result_payload, parsed.start_frame) != LIBRDP_STATUS_OK ||
        rdp_buffer_append_u32_le(result_payload,
                                 usbd_status == RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS ?
                                     parsed.packet_count :
                                 0u) != LIBRDP_STATUS_OK ||
        rdp_buffer_append_u32_le(result_payload, parsed.error_count) != LIBRDP_STATUS_OK)
    {
        free(buffer);
        return RDP_USB_REDIRECTION_USBD_STATUS_NO_MEMORY;
    }
    if (usbd_status == RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
    {
        payload_offset = 0;
        for (uint32_t i = 0; i < parsed.packet_count; i++)
        {
            uint32_t packet_status = packets[i].status;
            uint32_t packet_len = packets[i].actual_length;

            if (packet_status != RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
                error_count++;
            if (rdp_buffer_append_u32_le(result_payload, payload_offset) != LIBRDP_STATUS_OK ||
                rdp_buffer_append_u32_le(result_payload, packet_len) != LIBRDP_STATUS_OK ||
                rdp_buffer_append_u32_le(result_payload, packet_status) != LIBRDP_STATUS_OK)
            {
                free(buffer);
                return RDP_USB_REDIRECTION_USBD_STATUS_NO_MEMORY;
            }
            if (packet_len <= parsed.output_buffer_size - payload_offset)
                payload_offset += packet_len;
        }
        if (result_payload->length >= 12u)
        {
            result_payload->data[8] = (uint8_t)(error_count & 0xffu);
            result_payload->data[9] = (uint8_t)((error_count >> 8u) & 0xffu);
            result_payload->data[10] = (uint8_t)((error_count >> 16u) & 0xffu);
            result_payload->data[11] = (uint8_t)((error_count >> 24u) & 0xffu);
        }
        if (transfer->header.function_id == RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST &&
            buffer && actual_total > 0)
        {
            *output = buffer;
            *output_len = actual_total;
            buffer = NULL;
        }
    }
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.urbdrc.isoch_transfer",
                    "interface_id=%u endpoint=%u flags=%u direction=%u packets=%u requested=%u actual=%u usbd_status=%u",
                    transfer->header.interface_id,
                    endpoint,
                    parsed.transfer_flags,
                    transfer->header.function_id == RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST ? 1u : 0u,
                    parsed.packet_count,
                    parsed.output_buffer_size,
                    actual_total,
                    usbd_status);
    free(buffer);
    return usbd_status;
}

/*
 * Purpose: resolve Microsoft OS feature descriptor requests at the USB backend
 * boundary without blocking the dispatch loop on synchronous provider calls.
 * Invariant: parsed request lengths are bounded before transfer buffers are
 * allocated, and returned bytes are copied only into caller-owned completion
 * buffers. Failure policy: short vendor-code probes are rejected as STALL,
 * while backend timeout, cancel, and unplug statuses are propagated unchanged.
 */
static uint32_t rdp_session_usb_complete_os_feature_descriptor_request(
    librdp_session* session,
    rdp_usb_backend_device* device,
    const rdp_usb_redirection_transfer* transfer,
    uint8_t** output,
    uint32_t* output_len)
{
    rdp_session_usb_os_feature_request request;
    uint8_t ms_string[18];
    uint8_t vendor_code = 0;
    uint8_t* buffer = NULL;
    uint32_t actual = 0;
    uint32_t usbd_status = RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;

    if (!session || !session->usb_libusb || !device || !transfer || !output || !output_len)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    *output = NULL;
    *output_len = 0;
    memset(ms_string, 0, sizeof(ms_string));
    if (rdp_session_usb_parse_os_feature_request(transfer, &request) != LIBRDP_STATUS_OK)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    if (request.output_buffer_size > UINT16_MAX)
        return RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    usbd_status = rdp_usb_backend_control_transfer(session->usb_libusb,
                                                   device->handle,
                                                   (uint8_t)((uint8_t)LIBUSB_ENDPOINT_IN |
                                                             request.recipient),
                                                   LIBUSB_REQUEST_GET_DESCRIPTOR,
                                                   0x03eeu,
                                                   0,
                                                   ms_string,
                                                   (uint32_t)sizeof(ms_string),
                                                   rdp_session_usb_transfer_timeout(session, 1000u),
                                                   &actual);
    if (usbd_status != RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
        return usbd_status;
    if (actual < 17u)
        return RDP_USB_REDIRECTION_USBD_STATUS_STALL_PID;
    vendor_code = ms_string[16];
    if (request.output_buffer_size > 0)
    {
        buffer = (uint8_t*)calloc(1, request.output_buffer_size);
        if (!buffer)
            return RDP_USB_REDIRECTION_USBD_STATUS_NO_MEMORY;
        if (transfer->header.function_id == RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST &&
            request.data_len > 0)
            memcpy(buffer, request.data, request.data_len);
    }
    actual = 0;
    usbd_status = rdp_usb_backend_control_transfer(session->usb_libusb,
                                                   device->handle,
                                                   (uint8_t)((uint8_t)LIBUSB_ENDPOINT_IN |
                                                             (uint8_t)LIBUSB_REQUEST_TYPE_VENDOR |
                                                             request.recipient),
                                                   vendor_code,
                                                   (uint16_t)(((uint16_t)request.interface_number << 8u) |
                                                              request.page_index),
                                                   request.feature_index,
                                                   buffer,
                                                   request.output_buffer_size,
                                                   rdp_session_usb_transfer_timeout(session, 1000u),
                                                   &actual);
    if (usbd_status != RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
    {
        free(buffer);
        return usbd_status;
    }
    if (buffer && actual > 0)
    {
        *output = buffer;
        *output_len = actual;
    }
    else
        free(buffer);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.urbdrc.os_feature_descriptor",
                    "interface_id=%u recipient=%u interface_number=%u page=%u feature=%u requested=%u actual=%d",
                    transfer->header.interface_id,
                    request.recipient,
                    request.interface_number,
                    request.page_index,
                    request.feature_index,
                    request.output_buffer_size,
                    (int)actual);
    return RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS;
}
#endif

typedef struct rdp_session_usb_transfer_result
{
    uint32_t usbd_status;
    uint8_t* output;
    uint32_t output_len;
    rdp_buffer result_payload;
} rdp_session_usb_transfer_result;

static void rdp_session_usb_transfer_result_free(rdp_session_usb_transfer_result* result)
{
    if (!result)
        return;
    free(result->output);
    rdp_buffer_free(&result->result_payload);
    memset(result, 0, sizeof(*result));
}

/*
 * Execute one validated USB transfer against the host backend and normalize
 * backend-specific results into URBDRC status plus optional payload bytes. This
 * boundary keeps libusb ownership and error mapping out of the protocol writer.
 */
static librdp_status rdp_session_usb_execute_transfer(librdp_session* session,
                                                      const rdp_usb_redirection_transfer* transfer,
                                                      rdp_session_usb_transfer_result* result)
{
    uint32_t usbd_status = RDP_USB_REDIRECTION_USBD_STATUS_INVALID_URB_FUNCTION;
    uint8_t* output = NULL;
    uint32_t output_len = 0;
    rdp_buffer result_payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !transfer || !result)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));
    rdp_buffer_init(&result_payload);
#ifdef RDP_HAVE_LIBUSB
    {
        rdp_usb_backend_device* device =
            rdp_session_usb_device_by_interface_mut(session, transfer->header.interface_id);

        if (!device || !device->handle)
        {
            usbd_status = RDP_USB_REDIRECTION_USBD_STATUS_DEVICE_GONE;
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_SELECT_CONFIGURATION)
        {
            usbd_status = rdp_session_usb_complete_select_configuration(session,
                                                                        device,
                                                                        transfer,
                                                                        &result_payload);
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_SELECT_INTERFACE)
        {
            usbd_status = rdp_session_usb_complete_select_interface(device,
                                                                    transfer,
                                                                    &result_payload);
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_PIPE_REQUEST)
        {
            usbd_status = rdp_session_usb_complete_pipe_request(device, transfer, 0);
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_GET_CURRENT_FRAME_NUMBER)
        {
            usbd_status = rdp_session_usb_make_u32_output(rdp_session_usb_bus_time(),
                                                          &result_payload) == LIBRDP_STATUS_OK ?
                              RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS :
                              RDP_USB_REDIRECTION_USBD_STATUS_NO_MEMORY;
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER_EX)
        {
            rdp_session_usb_control_transfer control;

            status = rdp_session_usb_parse_control_transfer(transfer, &control);
            if (status != LIBRDP_STATUS_OK)
                usbd_status = RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
            else if (control.output_buffer_size > 0)
            {
                output = (uint8_t*)malloc(control.output_buffer_size);
                if (!output)
                    usbd_status = RDP_USB_REDIRECTION_USBD_STATUS_NO_MEMORY;
                else
                {
                    uint32_t actual = 0;
                    uint32_t timeout = rdp_session_usb_transfer_timeout(session, control.timeout);

                    if (transfer->header.function_id == RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST &&
                        control.data_len > 0)
                        memcpy(output, control.data, control.data_len);
                    usbd_status = rdp_usb_backend_control_transfer(session->usb_libusb,
                                                                   device->handle,
                                                                   control.request_type,
                                                                   control.request,
                                                                   control.value,
                                                                   control.index,
                                                                   output,
                                                                   control.output_buffer_size,
                                                                   timeout,
                                                                   &actual);
                    if (usbd_status == RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS &&
                        (control.request_type & LIBUSB_ENDPOINT_IN) != 0)
                        output_len = actual;
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.urbdrc.control_transfer",
                                    "interface_id=%u endpoint=%u request=%u value=%u index=%u flags=%u direction=%u requested=%u actual=%u timeout_ms=%u usbd_status=%u",
                                    transfer->header.interface_id,
                                    control.endpoint,
                                    control.request,
                                    control.value,
                                    control.index,
                                    control.transfer_flags,
                                    (control.request_type & LIBUSB_ENDPOINT_IN) != 0 ? 1u : 0u,
                                    control.output_buffer_size,
                                    actual,
                                    timeout,
                                    usbd_status);
                }
            }
            else
            {
                uint32_t actual = 0;
                uint32_t timeout = rdp_session_usb_transfer_timeout(session, control.timeout);

                usbd_status = rdp_usb_backend_control_transfer(session->usb_libusb,
                                                               device->handle,
                                                               control.request_type,
                                                               control.request,
                                                               control.value,
                                                               control.index,
                                                               NULL,
                                                               0,
                                                               timeout,
                                                               &actual);
            }
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_GET_DESCRIPTOR_FROM_DEVICE)
        {
            usbd_status = rdp_session_usb_complete_descriptor_request(session,
                                                                      device,
                                                                      transfer,
                                                                      0x00u,
                                                                      1,
                                                                      &output,
                                                                      &output_len);
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_SET_DESCRIPTOR_TO_DEVICE)
        {
            usbd_status = rdp_session_usb_complete_descriptor_request(session,
                                                                      device,
                                                                      transfer,
                                                                      0x00u,
                                                                      0,
                                                                      &output,
                                                                      &output_len);
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_GET_DESCRIPTOR_FROM_INTERFACE)
        {
            usbd_status = rdp_session_usb_complete_descriptor_request(session,
                                                                      device,
                                                                      transfer,
                                                                      0x01u,
                                                                      1,
                                                                      &output,
                                                                      &output_len);
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_SET_DESCRIPTOR_TO_INTERFACE)
        {
            usbd_status = rdp_session_usb_complete_descriptor_request(session,
                                                                      device,
                                                                      transfer,
                                                                      0x01u,
                                                                      0,
                                                                      &output,
                                                                      &output_len);
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_GET_DESCRIPTOR_FROM_ENDPOINT)
        {
            usbd_status = rdp_session_usb_complete_descriptor_request(session,
                                                                      device,
                                                                      transfer,
                                                                      0x02u,
                                                                      1,
                                                                      &output,
                                                                      &output_len);
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_SET_DESCRIPTOR_TO_ENDPOINT)
        {
            usbd_status = rdp_session_usb_complete_descriptor_request(session,
                                                                      device,
                                                                      transfer,
                                                                      0x02u,
                                                                      0,
                                                                      &output,
                                                                      &output_len);
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_DEVICE ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_CLEAR_FEATURE_TO_DEVICE ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_INTERFACE ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_CLEAR_FEATURE_TO_INTERFACE ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_ENDPOINT ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_CLEAR_FEATURE_TO_ENDPOINT ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_OTHER ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_CLEAR_FEATURE_TO_OTHER)
        {
            uint8_t recipient = 0;
            uint8_t set_feature =
                (transfer->urb.function == RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_DEVICE ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_INTERFACE ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_ENDPOINT ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_OTHER) ?
                    1u :
                    0u;

            if (transfer->urb.function == RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_INTERFACE ||
                transfer->urb.function == RDP_USB_REDIRECTION_URB_CLEAR_FEATURE_TO_INTERFACE)
                recipient = 0x01u;
            else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_ENDPOINT ||
                     transfer->urb.function == RDP_USB_REDIRECTION_URB_CLEAR_FEATURE_TO_ENDPOINT)
                recipient = 0x02u;
            else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_OTHER ||
                     transfer->urb.function == RDP_USB_REDIRECTION_URB_CLEAR_FEATURE_TO_OTHER)
                recipient = 0x03u;
            usbd_status = rdp_session_usb_complete_feature_request(session,
                                                                   device,
                                                                   transfer,
                                                                   recipient,
                                                                   set_feature,
                                                                   &output,
                                                                   &output_len);
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_GET_STATUS_FROM_DEVICE ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_GET_STATUS_FROM_INTERFACE ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_GET_STATUS_FROM_ENDPOINT ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_GET_STATUS_FROM_OTHER)
        {
            uint8_t recipient = 0;

            if (transfer->urb.function == RDP_USB_REDIRECTION_URB_GET_STATUS_FROM_INTERFACE)
                recipient = 0x01u;
            else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_GET_STATUS_FROM_ENDPOINT)
                recipient = 0x02u;
            else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_GET_STATUS_FROM_OTHER)
                recipient = 0x03u;
            usbd_status = rdp_session_usb_complete_get_status_request(session,
                                                                      device,
                                                                      transfer,
                                                                      recipient,
                                                                      &output,
                                                                      &output_len);
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_VENDOR_DEVICE ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_VENDOR_INTERFACE ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_VENDOR_ENDPOINT ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_VENDOR_OTHER ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_CLASS_DEVICE ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_CLASS_INTERFACE ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_CLASS_ENDPOINT ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_CLASS_OTHER)
        {
            uint8_t type = (transfer->urb.function == RDP_USB_REDIRECTION_URB_CLASS_DEVICE ||
                            transfer->urb.function == RDP_USB_REDIRECTION_URB_CLASS_INTERFACE ||
                            transfer->urb.function == RDP_USB_REDIRECTION_URB_CLASS_ENDPOINT ||
                            transfer->urb.function == RDP_USB_REDIRECTION_URB_CLASS_OTHER) ?
                               0x20u :
                               0x40u;
            uint8_t recipient = 0;

            if (transfer->urb.function == RDP_USB_REDIRECTION_URB_VENDOR_INTERFACE ||
                transfer->urb.function == RDP_USB_REDIRECTION_URB_CLASS_INTERFACE)
                recipient = 0x01u;
            else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_VENDOR_ENDPOINT ||
                     transfer->urb.function == RDP_USB_REDIRECTION_URB_CLASS_ENDPOINT)
                recipient = 0x02u;
            else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_VENDOR_OTHER ||
                     transfer->urb.function == RDP_USB_REDIRECTION_URB_CLASS_OTHER)
                recipient = 0x03u;
            usbd_status = rdp_session_usb_complete_vendor_class_request(session,
                                                                        device,
                                                                        transfer,
                                                                        type,
                                                                        recipient,
                                                                        &output,
                                                                        &output_len);
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_CONTROL_GET_CONFIGURATION_REQUEST)
        {
            usbd_status = rdp_session_usb_complete_get_configuration_request(session,
                                                                             device,
                                                                             transfer,
                                                                             &output,
                                                                             &output_len);
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_CONTROL_GET_INTERFACE_REQUEST)
        {
            usbd_status = rdp_session_usb_complete_get_interface_request(session,
                                                                         device,
                                                                         transfer,
                                                                         &output,
                                                                         &output_len);
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_SYNC_RESET_PIPE_AND_CLEAR_STALL ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_SYNC_RESET_PIPE ||
                 transfer->urb.function == RDP_USB_REDIRECTION_URB_SYNC_CLEAR_STALL)
        {
            usbd_status = rdp_session_usb_complete_pipe_request(device, transfer, 1);
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_BULK_OR_INTERRUPT_TRANSFER)
        {
            rdp_session_usb_pipe_transfer pipe;
            uint8_t endpoint = 0;
            uint8_t transfer_type = LIBUSB_TRANSFER_TYPE_BULK;

            status = rdp_session_usb_parse_pipe_transfer(transfer, &pipe);
            if (status != LIBRDP_STATUS_OK)
            {
                usbd_status = RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
            }
            else
            {
                uint32_t actual = 0;
                uint32_t timeout = rdp_session_usb_transfer_timeout(session, 10000u);

                endpoint = pipe.endpoint;
                if (transfer->header.function_id == RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST)
                    endpoint |= LIBUSB_ENDPOINT_IN;
                else
                    endpoint &= (uint8_t)~LIBUSB_ENDPOINT_IN;
                usbd_status = rdp_usb_backend_claim_endpoint(device, endpoint, &transfer_type);
                if (usbd_status == RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
                {
                    if (transfer->header.function_id == RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST)
                    {
                        if (pipe.output_buffer_size > 0)
                        {
                            output = (uint8_t*)malloc(pipe.output_buffer_size);
                            if (!output)
                                usbd_status = RDP_USB_REDIRECTION_USBD_STATUS_NO_MEMORY;
                        }
                        if (usbd_status == RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
                        {
                            usbd_status = rdp_usb_backend_bulk_or_interrupt_transfer(
                                session->usb_libusb,
                                device->handle,
                                endpoint,
                                transfer_type,
                                output,
                                pipe.output_buffer_size,
                                timeout,
                                &actual);
                            if (usbd_status == RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS)
                                output_len = actual;
                        }
                    }
                    else
                    {
                        usbd_status = rdp_usb_backend_bulk_or_interrupt_transfer(
                            session->usb_libusb,
                            device->handle,
                            endpoint,
                            transfer_type,
                            (uint8_t*)pipe.data,
                            pipe.data_len,
                            timeout,
                            &actual);
                    }
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.urbdrc.pipe_transfer",
                                    "interface_id=%u endpoint=%u type=%u flags=%u direction=%u requested=%u actual=%u timeout_ms=%u usbd_status=%u",
                                    transfer->header.interface_id,
                                    endpoint,
                                    transfer_type,
                                    pipe.transfer_flags,
                                    transfer->header.function_id ==
                                            RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST ?
                                        1u :
                                        0u,
                                    pipe.output_buffer_size,
                                    actual,
                                    timeout,
                                    usbd_status);
                }
            }
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_ISOCH_TRANSFER)
        {
            usbd_status = rdp_session_usb_complete_iso_transfer(session,
                                                                device,
                                                                transfer,
                                                                &result_payload,
                                                                &output,
                                                                &output_len);
        }
        else if (transfer->urb.function == RDP_USB_REDIRECTION_URB_GET_OS_FEATURE_DESCRIPTOR_REQUEST)
        {
            usbd_status = rdp_session_usb_complete_os_feature_descriptor_request(session,
                                                                                 device,
                                                                                 transfer,
                                                                                 &output,
                                                                                 &output_len);
        }
    }
#else
    (void)transfer;
    usbd_status = RDP_USB_REDIRECTION_USBD_STATUS_NOT_SUPPORTED;
#endif
    if (status != LIBRDP_STATUS_OK)
    {
        free(output);
        rdp_buffer_free(&result_payload);
        return status;
    }
    result->usbd_status = usbd_status;
    result->output = output;
    result->output_len = output_len;
    result->result_payload = result_payload;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_usb_complete_transfer(librdp_session* session,
                                                       const rdp_usb_redirection_transfer* transfer)
{
    rdp_session_usb_transfer_result result;
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_session_usb_execute_transfer(session, transfer, &result);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_usb_send_urb_completion_payload(
            session,
            transfer,
            result.usbd_status,
            result.result_payload.data,
            (uint32_t)result.result_payload.length,
            result.usbd_status == RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS ? result.output : NULL,
            result.usbd_status == RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS ? result.output_len : 0,
            "client.urbdrc.urb.completion");
    rdp_session_usb_transfer_result_free(&result);
    return status;
}

/*
 * Classify a submitted USB URB as an IN or OUT transfer using the URB function
 * and direction bits embedded in the request payload. This keeps transfer
 * completion framing consistent even for vendor/class requests with different
 * header layouts; invalid payloads fall back to the conservative IN policy.
 */
static uint32_t rdp_session_usb_submit_urb_function_id(const uint8_t* ts_urb,
                                                       uint32_t cb_ts_urb,
                                                       const rdp_usb_redirection_urb_header* urb,
                                                       uint32_t output_buffer_size)
{
    size_t offset = RDP_SESSION_USB_URB_HEADER_LENGTH;

    if (!ts_urb || !urb)
        return RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST;
    switch (urb->function)
    {
        case RDP_USB_REDIRECTION_URB_SELECT_CONFIGURATION:
        case RDP_USB_REDIRECTION_URB_SELECT_INTERFACE:
        case RDP_USB_REDIRECTION_URB_PIPE_REQUEST:
        case RDP_USB_REDIRECTION_URB_GET_CURRENT_FRAME_NUMBER:
        case RDP_USB_REDIRECTION_URB_GET_DESCRIPTOR_FROM_DEVICE:
        case RDP_USB_REDIRECTION_URB_GET_DESCRIPTOR_FROM_INTERFACE:
        case RDP_USB_REDIRECTION_URB_GET_DESCRIPTOR_FROM_ENDPOINT:
        case RDP_USB_REDIRECTION_URB_GET_STATUS_FROM_DEVICE:
        case RDP_USB_REDIRECTION_URB_GET_STATUS_FROM_INTERFACE:
        case RDP_USB_REDIRECTION_URB_GET_STATUS_FROM_ENDPOINT:
        case RDP_USB_REDIRECTION_URB_GET_STATUS_FROM_OTHER:
        case RDP_USB_REDIRECTION_URB_GET_OS_FEATURE_DESCRIPTOR_REQUEST:
        case RDP_USB_REDIRECTION_URB_CONTROL_GET_CONFIGURATION_REQUEST:
        case RDP_USB_REDIRECTION_URB_CONTROL_GET_INTERFACE_REQUEST:
        case RDP_USB_REDIRECTION_URB_SYNC_RESET_PIPE_AND_CLEAR_STALL:
        case RDP_USB_REDIRECTION_URB_SYNC_RESET_PIPE:
        case RDP_USB_REDIRECTION_URB_SYNC_CLEAR_STALL:
            return RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST;
        case RDP_USB_REDIRECTION_URB_SET_DESCRIPTOR_TO_DEVICE:
        case RDP_USB_REDIRECTION_URB_SET_DESCRIPTOR_TO_INTERFACE:
        case RDP_USB_REDIRECTION_URB_SET_DESCRIPTOR_TO_ENDPOINT:
        case RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_DEVICE:
        case RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_INTERFACE:
        case RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_ENDPOINT:
        case RDP_USB_REDIRECTION_URB_SET_FEATURE_TO_OTHER:
        case RDP_USB_REDIRECTION_URB_CLEAR_FEATURE_TO_DEVICE:
        case RDP_USB_REDIRECTION_URB_CLEAR_FEATURE_TO_INTERFACE:
        case RDP_USB_REDIRECTION_URB_CLEAR_FEATURE_TO_ENDPOINT:
        case RDP_USB_REDIRECTION_URB_CLEAR_FEATURE_TO_OTHER:
            return RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST;
        case RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER:
        case RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER_EX:
            offset += 8u;
            if (urb->function == RDP_USB_REDIRECTION_URB_CONTROL_TRANSFER_EX)
                offset += 4u;
            return cb_ts_urb > offset && (ts_urb[offset] & 0x80u) != 0 ?
                RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST :
                RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST;
        case RDP_USB_REDIRECTION_URB_BULK_OR_INTERRUPT_TRANSFER:
        case RDP_USB_REDIRECTION_URB_ISOCH_TRANSFER:
        case RDP_USB_REDIRECTION_URB_VENDOR_DEVICE:
        case RDP_USB_REDIRECTION_URB_VENDOR_INTERFACE:
        case RDP_USB_REDIRECTION_URB_VENDOR_ENDPOINT:
        case RDP_USB_REDIRECTION_URB_VENDOR_OTHER:
        case RDP_USB_REDIRECTION_URB_CLASS_DEVICE:
        case RDP_USB_REDIRECTION_URB_CLASS_INTERFACE:
        case RDP_USB_REDIRECTION_URB_CLASS_ENDPOINT:
        case RDP_USB_REDIRECTION_URB_CLASS_OTHER:
            return cb_ts_urb >= offset + 4u &&
                       (rdp_session_read_u32_le_unaligned(ts_urb + offset) &
                        RDP_USB_REDIRECTION_TRANSFER_DIRECTION) != 0 ?
                RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST :
                RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST;
        default:
            return output_buffer_size > 8u ? RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST :
                                             RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST;
    }
}

static librdp_status rdp_session_usb_control_to_transfer(
    const rdp_usb_redirection_io_control* control,
    rdp_usb_redirection_transfer* transfer)
{
    rdp_usb_redirection_urb_header urb;
    uint32_t function_id = 0;

    if (!control || !transfer || !control->input_buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_usb_redirection_parse_urb_header(control->input_buffer,
                                             control->input_buffer_len,
                                             &urb) != LIBRDP_STATUS_OK ||
        urb.size != control->input_buffer_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    function_id = rdp_session_usb_submit_urb_function_id(control->input_buffer,
                                                         control->input_buffer_len,
                                                         &urb,
                                                         control->output_buffer_size);
    memset(transfer, 0, sizeof(*transfer));
    transfer->header = control->header;
    transfer->header.function_id = function_id;
    transfer->header.has_function_id = 1;
    transfer->cb_ts_urb = control->input_buffer_len;
    transfer->ts_urb = control->input_buffer;
    transfer->urb = urb;
    transfer->output_buffer_size = control->output_buffer_size;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_usb_complete_submit_urb_control(
    librdp_session* session,
    const rdp_usb_redirection_io_control* control,
    rdp_buffer* output,
    uint32_t* usbd_status)
{
    rdp_usb_redirection_transfer transfer;
    rdp_session_usb_transfer_result result;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !control || !output || !usbd_status)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *usbd_status = RDP_USB_REDIRECTION_USBD_STATUS_INVALID_PARAMETER;
    memset(&result, 0, sizeof(result));
    status = rdp_session_usb_control_to_transfer(control, &transfer);
    if (status != LIBRDP_STATUS_OK)
        return rdp_session_usb_make_urb_result(*usbd_status, output);
    status = rdp_session_usb_execute_transfer(session, &transfer, &result);
    if (status == LIBRDP_STATUS_OK)
    {
        *usbd_status = result.usbd_status;
        status = rdp_session_usb_make_urb_result_payload(result.usbd_status,
                                                         result.result_payload.data,
                                                         (uint32_t)result.result_payload.length,
                                                         output);
    }
    if (status == LIBRDP_STATUS_OK &&
        result.usbd_status == RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS &&
        result.output_len > 0)
        status = rdp_buffer_append(output, result.output, result.output_len);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.submit_urb",
                        "interface_id=%u request_id=%u urb_function=%u direction_function=%u usbd_status=%u response_len=%u",
                        control->header.interface_id,
                        transfer.urb.request_id,
                        transfer.urb.function,
                        transfer.header.function_id,
                        result.usbd_status,
                        (unsigned)output->length);
    rdp_session_usb_transfer_result_free(&result);
    return status;
}

/*
 * URBDRC packets describe host USB operations requested by the server. Route
 * only after validating the common header so backend execution never observes
 * truncated request structures or stale interface IDs across failure paths.
 */
librdp_status rdp_session_handle_usb_redirection_message(librdp_session* session,
                                                                const uint8_t* data,
                                                                size_t data_len)
{
    rdp_usb_redirection_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_usb_redirection_parse_header(data, data_len, 1, &header);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.pdu.invalid",
                        "dvc_channel_id=%u payload_len=%u status=%s",
                        session->usb_redirection_channel_id,
                        (unsigned)data_len,
                        librdp_status_string(status));
        return status;
    }
    rdp_trace_event_level(RDP_TRACE_CLIENT,
                          RDP_TRACE_LEVEL_DEBUG,
                          "client.urbdrc.pdu",
                          "dvc_channel_id=%u interface_id=%u mask=%u message_id=%u function_id=%u payload_len=%u",
                          session->usb_redirection_channel_id,
                          header.interface_id,
                          header.mask,
                          header.message_id,
                          header.function_id,
                          (unsigned)header.payload_len);

    if (header.interface_id == RDP_USB_REDIRECTION_INTERFACE_CAPABILITIES &&
        header.mask == RDP_USB_REDIRECTION_MASK_NONE &&
        header.function_id == RDP_USB_REDIRECTION_FN_EXCHANGE_CAPABILITY)
    {
        rdp_usb_redirection_capability_exchange exchange;
        rdp_buffer response;
        rdp_buffer add_channel;

        rdp_buffer_init(&response);
        rdp_buffer_init(&add_channel);
        status = rdp_usb_redirection_parse_capability_request(data, data_len, &exchange);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_usb_redirection_write_capability_response(&response,
                                                                   exchange.header.message_id,
                                                                   exchange.capability_value,
                                                                   RDP_SESSION_HRESULT_OK);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_usb_redirection_packet(session,
                                                             &response,
                                                             "client.urbdrc.capability.response");
        if (status == LIBRDP_STATUS_OK)
            status = rdp_usb_redirection_write_add_virtual_channel(&add_channel,
                                                                   rdp_session_usb_next_message_id(session));
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_usb_redirection_packet(session,
                                                             &add_channel,
                                                             "client.urbdrc.add_virtual_channel");
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.capability",
                        "dvc_channel_id=%u capability=%u enabled=%u status=%s",
                        session->usb_redirection_channel_id,
                        status == LIBRDP_STATUS_OK ? exchange.capability_value : 0u,
                        rdp_session_feature_ready_for_negotiation(session, LIBRDP_FEATURE_USB),
                        librdp_status_string(status));
        rdp_buffer_free(&add_channel);
        rdp_buffer_free(&response);
        return status;
    }
    if (header.mask == RDP_USB_REDIRECTION_MASK_PROXY &&
        header.function_id == RDP_USB_REDIRECTION_FN_CHANNEL_CREATED)
    {
        rdp_usb_redirection_channel_created created;

        status = rdp_usb_redirection_parse_channel_created(data, data_len, header.interface_id, &created);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session->usb_redirection_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.channel_created",
                        "dvc_channel_id=%u interface_id=%u version=%u.%u capabilities=%u",
                        session->usb_redirection_channel_id,
                        header.interface_id,
                        created.major_version,
                        created.minor_version,
                        created.capabilities);
        return rdp_session_usb_send_device_announcements(session);
    }
    if (header.mask == RDP_USB_REDIRECTION_MASK_PROXY &&
        header.function_id == RDP_USB_REDIRECTION_FN_REGISTER_REQUEST_CALLBACK)
    {
        rdp_usb_redirection_register_callback callback;

        status = rdp_usb_redirection_parse_register_callback(data, data_len, &callback);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session->usb_request_completion_ready = callback.has_request_completion ? 1u : 0u;
        session->usb_request_completion_interface_id =
            callback.has_request_completion ? callback.request_completion : 0u;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.register_callback",
                        "dvc_channel_id=%u interface_id=%u callback_ready=%u callback_interface_id=%u",
                        session->usb_redirection_channel_id,
                        callback.header.interface_id,
                        session->usb_request_completion_ready,
                        session->usb_request_completion_interface_id);
        return LIBRDP_STATUS_OK;
    }
    if (header.mask == RDP_USB_REDIRECTION_MASK_PROXY &&
        header.function_id == RDP_USB_REDIRECTION_FN_QUERY_DEVICE_TEXT)
    {
        char description[256];
        rdp_usb_redirection_query_device_text query;
        rdp_buffer text;
        rdp_buffer response;

        memset(description, 0, sizeof(description));
        rdp_buffer_init(&text);
        rdp_buffer_init(&response);
        status = rdp_usb_redirection_parse_query_device_text(data, data_len, &query);
#ifdef RDP_HAVE_LIBUSB
        if (status == LIBRDP_STATUS_OK)
            (void)rdp_session_usb_device_text(session,
                                              query.header.interface_id,
                                              query.text_type,
                                              description,
                                              sizeof(description));
#else
        if (status == LIBRDP_STATUS_OK)
            snprintf(description, sizeof(description), "USB redirected device");
#endif
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_utf8_to_utf16le(description, &text, 1);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_usb_redirection_write_query_device_text_response(&response,
                                                                          query.header.interface_id,
                                                                          query.header.message_id,
                                                                          text.data,
                                                                          (uint32_t)text.length,
                                                                          RDP_SESSION_HRESULT_OK);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_usb_redirection_packet(session,
                                                             &response,
                                                             "client.urbdrc.query_device_text.response");
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.query_device_text",
                        "dvc_channel_id=%u interface_id=%u text_type=%u locale_id=%u status=%s",
                        session->usb_redirection_channel_id,
                        header.interface_id,
                        status == LIBRDP_STATUS_OK ? query.text_type : 0u,
                        status == LIBRDP_STATUS_OK ? query.locale_id : 0u,
                        librdp_status_string(status));
        rdp_buffer_free(&response);
        rdp_buffer_free(&text);
        return status;
    }
    if (header.mask == RDP_USB_REDIRECTION_MASK_PROXY &&
        (header.function_id == RDP_USB_REDIRECTION_FN_IO_CONTROL ||
         header.function_id == RDP_USB_REDIRECTION_FN_INTERNAL_IO_CONTROL))
    {
        rdp_usb_redirection_io_control control;
        rdp_buffer output;
        uint32_t result = RDP_SESSION_HRESULT_FAIL;
        uint32_t usbd_status = RDP_USB_REDIRECTION_USBD_STATUS_NOT_SUPPORTED;

        rdp_buffer_init(&output);
        status = rdp_usb_redirection_parse_io_control(data, data_len, header.function_id, &control);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&output);
            return status;
        }
        if (control.header.function_id == RDP_USB_REDIRECTION_FN_IO_CONTROL)
        {
            if (control.io_control_code == RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_GET_PORT_STATUS)
            {
                status = rdp_session_usb_make_u32_output(
                    rdp_session_usb_port_status(session, control.header.interface_id),
                    &output);
                result = RDP_SESSION_HRESULT_OK;
            }
            else if (control.io_control_code == RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_RESET_PORT ||
                     control.io_control_code == RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_CYCLE_PORT)
            {
#ifdef RDP_HAVE_LIBUSB
                usbd_status = rdp_session_usb_reset_interface(session, control.header.interface_id);
                result = usbd_status == RDP_USB_REDIRECTION_USBD_STATUS_SUCCESS ?
                             RDP_SESSION_HRESULT_OK :
                             RDP_SESSION_HRESULT_FAIL;
#else
                usbd_status = RDP_USB_REDIRECTION_USBD_STATUS_NOT_SUPPORTED;
                result = RDP_SESSION_HRESULT_FAIL;
#endif
            }
            else if (control.io_control_code ==
                     RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_SUBMIT_IDLE_NOTIFICATION)
            {
                result = RDP_SESSION_HRESULT_OK;
            }
            else if (control.io_control_code == RDP_USB_REDIRECTION_IOCTL_INTERNAL_USB_SUBMIT_URB)
            {
                status = rdp_session_usb_complete_submit_urb_control(session,
                                                                     &control,
                                                                     &output,
                                                                     &usbd_status);
                result = RDP_SESSION_HRESULT_OK;
            }
        }
        else if (control.io_control_code == RDP_USB_REDIRECTION_IOCTL_QUERY_BUS_TIME)
        {
            status = rdp_session_usb_make_u32_output(rdp_session_usb_bus_time(), &output);
            result = RDP_SESSION_HRESULT_OK;
        }
        if (status == LIBRDP_STATUS_OK &&
            result == RDP_SESSION_HRESULT_OK &&
            output.length > control.output_buffer_size)
        {
            output.length = 0;
            result = RDP_SESSION_HRESULT_FAIL;
        }
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.io_control",
                        "dvc_channel_id=%u interface_id=%u function_id=%u io_control=%u request_id=%u input_len=%u output_size=%u result=%u usbd_status=%u response_len=%u",
                        session->usb_redirection_channel_id,
                        control.header.interface_id,
                        control.header.function_id,
                        control.io_control_code,
                        control.request_id,
                        control.input_buffer_len,
                        control.output_buffer_size,
                        result,
                        usbd_status,
                        (unsigned)output.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_usb_send_io_completion(session,
                                                        control.request_id,
                                                        result,
                                                        (uint32_t)output.length,
                                                        output.data,
                                                        (uint32_t)output.length,
                                                        "client.urbdrc.io_control.completion");
        rdp_buffer_free(&output);
        return status;
    }
    if (header.mask == RDP_USB_REDIRECTION_MASK_PROXY &&
        (header.function_id == RDP_USB_REDIRECTION_FN_TRANSFER_IN_REQUEST ||
         header.function_id == RDP_USB_REDIRECTION_FN_TRANSFER_OUT_REQUEST))
    {
        rdp_usb_redirection_transfer transfer;

        status = rdp_usb_redirection_parse_transfer(data, data_len, header.function_id, &transfer);
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.transfer",
                        "dvc_channel_id=%u interface_id=%u function_id=%u urb_function=%u request_id=%u output_size=%u output_len=%u no_ack=%u",
                        session->usb_redirection_channel_id,
                        transfer.header.interface_id,
                        transfer.header.function_id,
                        transfer.urb.function,
                        transfer.urb.request_id,
                        transfer.output_buffer_size,
                        transfer.output_buffer_len,
                        transfer.urb.no_ack);
        return rdp_session_usb_complete_transfer(session, &transfer);
    }
    if (header.mask == RDP_USB_REDIRECTION_MASK_PROXY &&
        header.function_id == RDP_USB_REDIRECTION_FN_CANCEL_REQUEST)
    {
        rdp_usb_redirection_cancel_request cancel;

        status = rdp_usb_redirection_parse_cancel_request(data, data_len, &cancel);
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.cancel",
                        "dvc_channel_id=%u interface_id=%u request_id=%u",
                        session->usb_redirection_channel_id,
                        cancel.header.interface_id,
                        cancel.request_id);
        return LIBRDP_STATUS_OK;
    }
    if (header.mask == RDP_USB_REDIRECTION_MASK_PROXY &&
        header.function_id == RDP_USB_REDIRECTION_FN_RETRACT_DEVICE)
    {
        rdp_usb_redirection_retract_device retract;
        uint8_t released = 0;
#ifdef RDP_HAVE_LIBUSB
        rdp_usb_backend_device* device = NULL;
#endif

        status = rdp_usb_redirection_parse_retract_device(data, data_len, &retract);
        if (status != LIBRDP_STATUS_OK)
            return status;
#ifdef RDP_HAVE_LIBUSB
        device = rdp_session_usb_device_by_interface_mut(session, retract.header.interface_id);
        if (device && device->active)
        {
            rdp_usb_backend_release_device(device);
            released = 1;
        }
#endif
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.urbdrc.retract",
                        "dvc_channel_id=%u interface_id=%u reason=%u released=%u",
                        session->usb_redirection_channel_id,
                        retract.header.interface_id,
                        retract.reason,
                        released);
        return LIBRDP_STATUS_OK;
    }

    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.urbdrc.ignored",
                    "dvc_channel_id=%u interface_id=%u mask=%u function_id=%u payload_len=%u",
                    session->usb_redirection_channel_id,
                    header.interface_id,
                    header.mask,
                    header.function_id,
                    (unsigned)header.payload_len);
    return LIBRDP_STATUS_OK;
}
