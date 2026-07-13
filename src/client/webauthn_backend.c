/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: WebAuthn native backend adapters.
 * Invariants: CTAPHID frame sizes, sequence numbers, and device paths are
 * checked before any native authenticator operation.
 * Ownership: temporary native handles and buffers are released on every return
 * path; caller-owned response buffers receive only validated CTAP responses.
 * Threading: the FIDO2 backend is synchronous and bounded by CTAPHID timeouts;
 * it does not retain global device handles between calls.
 * Trust boundary: CTAP request and response payloads may contain credential
 * material and are intentionally excluded from trace output.
 */

#include "client/webauthn_backend.h"

#include "common/trace.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/rand.h>

#if defined(RDP_HAVE_FIDO2) && defined(__linux__)
#include <fido.h>
#endif

#define RDP_WEBAUTHN_BACKEND_CTAPHID_REPORT_LENGTH 64u
#define RDP_WEBAUTHN_BACKEND_CTAPHID_INIT_PAYLOAD_LENGTH 57u
#define RDP_WEBAUTHN_BACKEND_CTAPHID_CONT_PAYLOAD_LENGTH 59u
#define RDP_WEBAUTHN_BACKEND_CTAPHID_MAX_PAYLOAD \
    (57u + 128u * 59u)
#define RDP_WEBAUTHN_BACKEND_CTAPHID_BROADCAST_CID 0xffffffffu
#define RDP_WEBAUTHN_BACKEND_CTAPHID_CMD_INIT 0x86u
#define RDP_WEBAUTHN_BACKEND_CTAPHID_CMD_CBOR 0x90u
#define RDP_WEBAUTHN_BACKEND_CTAPHID_CMD_KEEPALIVE 0xbbu
#define RDP_WEBAUTHN_BACKEND_CTAPHID_CMD_ERROR 0xbfu
#define RDP_WEBAUTHN_BACKEND_CTAPHID_TIMEOUT_MS 60000u

static void rdp_webauthn_backend_copy_text(char* dst,
                                           size_t dst_len,
                                           const char* src,
                                           const char* fallback)
{
    const char* value = src && src[0] ? src : fallback;
    size_t length = value ? strlen(value) : 0;

    if (!dst || dst_len == 0)
        return;
    if (length >= dst_len)
        length = dst_len - 1u;
    if (length > 0)
        memcpy(dst, value, length);
    dst[length] = '\0';
}

void rdp_webauthn_backend_fido2_info_init(rdp_webauthn_backend_fido2_device* device)
{
    static const uint8_t fallback_guid[RDP_WEBAUTHN_GUID_LENGTH] = {
        0x6c, 0x69, 0x62, 0x72, 0x64, 0x70, 0x2d, 0x66,
        0x69, 0x64, 0x6f, 0x32, 0x30, 0x30, 0x30, 0x31
    };

    if (!device)
        return;
    memset(device, 0, sizeof(*device));
    memcpy(device->aaguid, fallback_guid, sizeof(device->aaguid));
    rdp_webauthn_backend_copy_text(device->manufacturer,
                                   sizeof(device->manufacturer),
                                   NULL,
                                   "FIDO2");
    rdp_webauthn_backend_copy_text(device->product,
                                   sizeof(device->product),
                                   NULL,
                                   "Authenticator");
    device->info.provider_type = "Hid";
    device->info.provider_name = "FIDO2";
    device->info.device_path = device->path;
    device->info.manufacturer = device->manufacturer;
    device->info.product = device->product;
    device->info.aaguid = device->aaguid;
    device->info.aaguid_len = sizeof(device->aaguid);
    device->info.max_msg_size = RDP_WEBAUTHN_BACKEND_CTAPHID_MAX_PAYLOAD;
    device->info.max_large_blob_size = 0;
    device->info.uv_status = 0;
    device->info.uv_retries = 0;
    device->info.transports = 1;
    device->info.status = 0;
}

#if defined(RDP_HAVE_FIDO2) && defined(__linux__)
static uint32_t rdp_webauthn_backend_ctaphid_read_u32_be(const uint8_t* data)
{
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) | (uint32_t)data[3];
}

static void rdp_webauthn_backend_ctaphid_write_u32_be(uint8_t* data, uint32_t value)
{
    data[0] = (uint8_t)((value >> 24) & 0xffu);
    data[1] = (uint8_t)((value >> 16) & 0xffu);
    data[2] = (uint8_t)((value >> 8) & 0xffu);
    data[3] = (uint8_t)(value & 0xffu);
}

static uint64_t rdp_webauthn_backend_time_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static int rdp_webauthn_backend_ctaphid_write_frame(int fd, const uint8_t* frame)
{
    ssize_t written = 0;

    if (fd < 0 || !frame)
        return 0;
    do
    {
        written = write(fd, frame, RDP_WEBAUTHN_BACKEND_CTAPHID_REPORT_LENGTH);
    } while (written < 0 && errno == EINTR);
    return written == (ssize_t)RDP_WEBAUTHN_BACKEND_CTAPHID_REPORT_LENGTH;
}

static int rdp_webauthn_backend_ctaphid_read_frame(int fd,
                                                   uint8_t* frame,
                                                   uint64_t deadline_ms)
{
    for (;;)
    {
        struct pollfd pfd;
        uint64_t now_ms = rdp_webauthn_backend_time_ms();
        int timeout = 0;
        ssize_t count = 0;

        if (deadline_ms <= now_ms)
            return 0;
        timeout = (int)(deadline_ms - now_ms);
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, timeout) < 0)
        {
            if (errno == EINTR)
                continue;
            return 0;
        }
        if ((pfd.revents & POLLIN) == 0)
            return 0;
        count = read(fd, frame, RDP_WEBAUTHN_BACKEND_CTAPHID_REPORT_LENGTH);
        if (count < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        return count == (ssize_t)RDP_WEBAUTHN_BACKEND_CTAPHID_REPORT_LENGTH;
    }
}

static librdp_status rdp_webauthn_backend_ctaphid_send(uint32_t cid,
                                                       uint8_t command,
                                                       const uint8_t* payload,
                                                       size_t payload_len,
                                                       int fd)
{
    uint8_t frame[RDP_WEBAUTHN_BACKEND_CTAPHID_REPORT_LENGTH];
    size_t offset = 0;
    size_t chunk = 0;
    uint8_t seq = 0;

    if (fd < 0 || (!payload && payload_len > 0) ||
        payload_len > RDP_WEBAUTHN_BACKEND_CTAPHID_MAX_PAYLOAD)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(frame, 0, sizeof(frame));
    rdp_webauthn_backend_ctaphid_write_u32_be(frame, cid);
    frame[4] = command;
    frame[5] = (uint8_t)((payload_len >> 8) & 0xffu);
    frame[6] = (uint8_t)(payload_len & 0xffu);
    chunk = payload_len < RDP_WEBAUTHN_BACKEND_CTAPHID_INIT_PAYLOAD_LENGTH ?
                payload_len :
                RDP_WEBAUTHN_BACKEND_CTAPHID_INIT_PAYLOAD_LENGTH;
    if (chunk > 0)
        memcpy(frame + 7u, payload, chunk);
    if (!rdp_webauthn_backend_ctaphid_write_frame(fd, frame))
        return LIBRDP_STATUS_IO_ERROR;
    offset = chunk;
    while (offset < payload_len)
    {
        size_t remaining = payload_len - offset;

        if (seq >= 128u)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        memset(frame, 0, sizeof(frame));
        rdp_webauthn_backend_ctaphid_write_u32_be(frame, cid);
        frame[4] = seq++;
        chunk = remaining < RDP_WEBAUTHN_BACKEND_CTAPHID_CONT_PAYLOAD_LENGTH ?
                    remaining :
                    RDP_WEBAUTHN_BACKEND_CTAPHID_CONT_PAYLOAD_LENGTH;
        memcpy(frame + 5u, payload + offset, chunk);
        if (!rdp_webauthn_backend_ctaphid_write_frame(fd, frame))
            return LIBRDP_STATUS_IO_ERROR;
        offset += chunk;
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Reassembles one CTAPHID response across initial and continuation reports.
 * Frame CID, command, total length, continuation sequence, and deadline are
 * validated before bytes enter the caller buffer, and CTAP payload contents are
 * never traced because they may contain credential material.
 */
static librdp_status rdp_webauthn_backend_ctaphid_recv(uint32_t cid,
                                                       uint8_t expected_command,
                                                       int fd,
                                                       rdp_buffer* payload,
                                                       uint32_t timeout_ms)
{
    uint8_t frame[RDP_WEBAUTHN_BACKEND_CTAPHID_REPORT_LENGTH];
    uint64_t deadline = rdp_webauthn_backend_time_ms() + timeout_ms;
    uint16_t total = 0;
    size_t copied = 0;
    uint8_t seq = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (fd < 0 || !payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (;;)
    {
        uint32_t frame_cid = 0;
        uint8_t command = 0;
        size_t chunk = 0;

        if (!rdp_webauthn_backend_ctaphid_read_frame(fd, frame, deadline))
            return LIBRDP_STATUS_TIMEOUT;
        frame_cid = rdp_webauthn_backend_ctaphid_read_u32_be(frame);
        command = frame[4];
        if (frame_cid != cid)
            continue;
        if (command == RDP_WEBAUTHN_BACKEND_CTAPHID_CMD_KEEPALIVE)
        {
            rdp_trace_event_level(RDP_TRACE_CLIENT,
                                  RDP_TRACE_LEVEL_DEBUG,
                                  "client.webauthn.fido2.keepalive",
                                  "status=%u",
                                  frame[7]);
            continue;
        }
        if (command == RDP_WEBAUTHN_BACKEND_CTAPHID_CMD_ERROR)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.webauthn.fido2.error",
                            "code=%u",
                            frame[7]);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (command != expected_command)
            continue;
        total = (uint16_t)(((uint16_t)frame[5] << 8) | (uint16_t)frame[6]);
        if (total > RDP_WEBAUTHN_BACKEND_CTAPHID_MAX_PAYLOAD)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        chunk = total < RDP_WEBAUTHN_BACKEND_CTAPHID_INIT_PAYLOAD_LENGTH ?
                    total :
                    RDP_WEBAUTHN_BACKEND_CTAPHID_INIT_PAYLOAD_LENGTH;
        status = rdp_buffer_append(payload, frame + 7u, chunk);
        if (status != LIBRDP_STATUS_OK)
            return status;
        copied = chunk;
        break;
    }
    while (copied < total)
    {
        uint32_t frame_cid = 0;
        size_t remaining = 0;
        size_t chunk = 0;

        if (!rdp_webauthn_backend_ctaphid_read_frame(fd, frame, deadline))
            return LIBRDP_STATUS_TIMEOUT;
        frame_cid = rdp_webauthn_backend_ctaphid_read_u32_be(frame);
        if (frame_cid != cid)
            continue;
        if (frame[4] == RDP_WEBAUTHN_BACKEND_CTAPHID_CMD_KEEPALIVE)
            continue;
        if ((frame[4] & 0x80u) != 0 || frame[4] != seq++)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        remaining = total - copied;
        chunk = remaining < RDP_WEBAUTHN_BACKEND_CTAPHID_CONT_PAYLOAD_LENGTH ?
                    remaining :
                    RDP_WEBAUTHN_BACKEND_CTAPHID_CONT_PAYLOAD_LENGTH;
        status = rdp_buffer_append(payload, frame + 5u, chunk);
        if (status != LIBRDP_STATUS_OK)
            return status;
        copied += chunk;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_webauthn_backend_ctaphid_init(int fd, uint32_t* cid)
{
    uint8_t nonce[8];
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (fd < 0 || !cid)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        return LIBRDP_STATUS_STATE;
    rdp_buffer_init(&response);
    status = rdp_webauthn_backend_ctaphid_send(RDP_WEBAUTHN_BACKEND_CTAPHID_BROADCAST_CID,
                                               RDP_WEBAUTHN_BACKEND_CTAPHID_CMD_INIT,
                                               nonce,
                                               sizeof(nonce),
                                               fd);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_webauthn_backend_ctaphid_recv(RDP_WEBAUTHN_BACKEND_CTAPHID_BROADCAST_CID,
                                                   RDP_WEBAUTHN_BACKEND_CTAPHID_CMD_INIT,
                                                   fd,
                                                   &response,
                                                   5000u);
    if (status == LIBRDP_STATUS_OK &&
        (response.length < 17u || memcmp(response.data, nonce, sizeof(nonce)) != 0))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
    {
        *cid = rdp_webauthn_backend_ctaphid_read_u32_be(response.data + 8u);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.webauthn.fido2.init",
                        "protocol=%u major=%u minor=%u build=%u caps=%u",
                        response.data[12],
                        response.data[13],
                        response.data[14],
                        response.data[15],
                        response.data[16]);
    }
    rdp_buffer_free(&response);
    return status;
}

static void rdp_webauthn_backend_fill_fido2_cbor_info(rdp_webauthn_backend_fido2_device* device)
{
    fido_dev_t* dev = NULL;
    fido_cbor_info_t* cbor = NULL;

    if (!device || device->path[0] == '\0')
        return;
    dev = fido_dev_new();
    cbor = fido_cbor_info_new();
    if (dev && cbor && fido_dev_open(dev, device->path) == FIDO_OK)
    {
        int retries = 0;

        if (fido_dev_get_cbor_info(dev, cbor) == FIDO_OK)
        {
            const unsigned char* guid = fido_cbor_info_aaguid_ptr(cbor);
            size_t guid_len = fido_cbor_info_aaguid_len(cbor);
            uint64_t max_msg = fido_cbor_info_maxmsgsiz(cbor);
            uint64_t max_blob = fido_cbor_info_maxlargeblob(cbor);

            if (guid && guid_len == sizeof(device->aaguid))
                memcpy(device->aaguid, guid, sizeof(device->aaguid));
            if (max_msg > 0 && max_msg < device->info.max_msg_size)
                device->info.max_msg_size = (uint32_t)max_msg;
            if (max_blob > UINT32_MAX)
                device->info.max_large_blob_size = UINT32_MAX;
            else
                device->info.max_large_blob_size = (uint32_t)max_blob;
        }
        if (fido_dev_get_uv_retry_count(dev, &retries) == FIDO_OK && retries >= 0)
            device->info.uv_retries = (uint32_t)retries;
        device->info.uv_status = fido_dev_supports_uv(dev) ? 2u : 0u;
        (void)fido_dev_close(dev);
    }
    fido_cbor_info_free(&cbor);
    fido_dev_free(&dev);
}

librdp_status rdp_webauthn_backend_select_fido2_device(
    const char* requested_path,
    rdp_webauthn_backend_fido2_device* device)
{
    fido_dev_info_t* list = NULL;
    size_t found = 0;
    size_t i = 0;
    int selected = 0;

    if (!device)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_webauthn_backend_fido2_info_init(device);
    fido_init(0);
    list = fido_dev_info_new(64);
    if (list && fido_dev_info_manifest(list, 64, &found) == FIDO_OK)
    {
        for (i = 0; i < found; i++)
        {
            const fido_dev_info_t* entry = fido_dev_info_ptr(list, i);
            const char* path = entry ? fido_dev_info_path(entry) : NULL;

            if (!path || (requested_path && strcmp(requested_path, path) != 0))
                continue;
            rdp_webauthn_backend_copy_text(device->path, sizeof(device->path), path, "");
            rdp_webauthn_backend_copy_text(device->manufacturer,
                                           sizeof(device->manufacturer),
                                           fido_dev_info_manufacturer_string(entry),
                                           "FIDO2");
            rdp_webauthn_backend_copy_text(device->product,
                                           sizeof(device->product),
                                           fido_dev_info_product_string(entry),
                                           "Authenticator");
            selected = 1;
            break;
        }
    }
    if (!selected && requested_path)
    {
        rdp_webauthn_backend_copy_text(device->path, sizeof(device->path), requested_path, "");
        selected = 1;
    }
    fido_dev_info_free(&list, 64);
    if (!selected || strncmp(device->path, "/dev/hidraw", 11u) != 0)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.webauthn.fido2.select.failed",
                        "requested=%u devices=%u",
                        requested_path ? 1u : 0u,
                        (unsigned)found);
        return LIBRDP_STATUS_UNSUPPORTED;
    }
    rdp_webauthn_backend_fill_fido2_cbor_info(device);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.webauthn.fido2.select",
                    "path=\"%s\" devices=%u max_msg_size=%u",
                    device->path,
                    (unsigned)found,
                    device->info.max_msg_size);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_webauthn_backend_fido2_exchange(
    const char* requested_path,
    const rdp_webauthn_request* request,
    rdp_webauthn_backend_fido2_device* device,
    rdp_buffer* ctap_response)
{
    int fd = -1;
    uint32_t cid = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!request || !device || !ctap_response || !request->request ||
        request->request_len == 0 ||
        request->request_len > RDP_WEBAUTHN_BACKEND_CTAPHID_MAX_PAYLOAD)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_webauthn_backend_select_fido2_device(requested_path, device);
    if (status != LIBRDP_STATUS_OK)
        return status;
    fd = open(device->path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.webauthn.fido2.open.failed",
                        "errno=%d",
                        errno);
        return LIBRDP_STATUS_IO_ERROR;
    }
    status = rdp_webauthn_backend_ctaphid_init(fd, &cid);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_webauthn_backend_ctaphid_send(cid,
                                                   RDP_WEBAUTHN_BACKEND_CTAPHID_CMD_CBOR,
                                                   request->request,
                                                   request->request_len,
                                                   fd);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_webauthn_backend_ctaphid_recv(cid,
                                                   RDP_WEBAUTHN_BACKEND_CTAPHID_CMD_CBOR,
                                                   fd,
                                                   ctap_response,
                                                   RDP_WEBAUTHN_BACKEND_CTAPHID_TIMEOUT_MS);
    close(fd);
    if (status == LIBRDP_STATUS_OK && ctap_response->length == 0)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.webauthn.fido2.exchange",
                    "status=%s request_len=%u response_len=%u",
                    librdp_status_string(status),
                    (unsigned)request->request_len,
                    (unsigned)ctap_response->length);
    return status;
}
#else
librdp_status rdp_webauthn_backend_select_fido2_device(
    const char* requested_path,
    rdp_webauthn_backend_fido2_device* device)
{
    (void)requested_path;
    rdp_webauthn_backend_fido2_info_init(device);
    return LIBRDP_STATUS_UNSUPPORTED;
}

librdp_status rdp_webauthn_backend_fido2_exchange(
    const char* requested_path,
    const rdp_webauthn_request* request,
    rdp_webauthn_backend_fido2_device* device,
    rdp_buffer* ctap_response)
{
    (void)requested_path;
    (void)request;
    (void)ctap_response;
    rdp_webauthn_backend_fido2_info_init(device);
    return LIBRDP_STATUS_UNSUPPORTED;
}
#endif
