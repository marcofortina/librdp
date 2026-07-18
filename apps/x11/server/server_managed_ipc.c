/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * Module: bounded serialization and peer authentication for managed-session
 * Unix sockets.
 * Invariants: fixed-width integers use little-endian wire order, strings carry
 * explicit lengths, and no partial frame is committed to caller state.
 * Ownership: temporary frame storage is stack-owned and cleansed before return.
 * Threading: functions contain no shared mutable state.
 * Trust boundary: local socket data remains untrusted even after kernel peer
 * credential lookup; message semantics are validated independently.
 */

#include "server_managed_ipc.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#if defined(__sun)
#include <ucred.h>
#endif

#define X11_MANAGED_IPC_HEADER_BYTES 24u
#define X11_MANAGED_IPC_MAGIC 0x534d524cu
#define X11_MANAGED_IPC_MAX_DIMENSION 16384u

typedef struct x11_managed_ipc_cursor
{
    uint8_t* data;
    size_t capacity;
    size_t offset;
} x11_managed_ipc_cursor;

static uint64_t x11_managed_ipc_now_ms(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0u;
    return (uint64_t)now.tv_sec * 1000u +
           (uint64_t)now.tv_nsec / 1000000u;
}

static int x11_managed_ipc_remaining_timeout(
    int timeout_ms,
    uint64_t deadline_ms)
{
    uint64_t now_ms = 0u;
    uint64_t remaining = 0u;

    if (timeout_ms < 0)
        return -1;
    now_ms = x11_managed_ipc_now_ms();
    if (now_ms >= deadline_ms)
        return 0;
    remaining = deadline_ms - now_ms;
    return remaining > (uint64_t)INT_MAX ? INT_MAX : (int)remaining;
}

/*
 * Wait for one socket direction while preserving a single deadline across
 * interrupted polls and partial I/O.
 */
static librdp_status x11_managed_ipc_wait(
    int descriptor,
    short events,
    int timeout_ms,
    uint64_t deadline_ms)
{
    struct pollfd poll_descriptor;
    int result = 0;

    memset(&poll_descriptor, 0, sizeof(poll_descriptor));
    poll_descriptor.fd = descriptor;
    poll_descriptor.events = events;
    do
    {
        int remaining =
            x11_managed_ipc_remaining_timeout(timeout_ms, deadline_ms);

        result = poll(&poll_descriptor, 1u, remaining);
    } while (result < 0 && errno == EINTR);
    if (result == 0)
        return LIBRDP_STATUS_TIMEOUT;
    if (result < 0)
        return LIBRDP_STATUS_IO_ERROR;
    if ((poll_descriptor.revents &
         (POLLERR | POLLHUP | POLLNVAL)) != 0)
        return LIBRDP_STATUS_IO_ERROR;
    if ((poll_descriptor.revents & events) == 0)
        return LIBRDP_STATUS_AGAIN;
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_managed_ipc_write_all(
    int descriptor,
    const uint8_t* data,
    size_t length,
    int timeout_ms)
{
    uint64_t deadline_ms =
        timeout_ms < 0
            ? 0u
            : x11_managed_ipc_now_ms() + (uint64_t)timeout_ms;
    size_t offset = 0u;

    while (offset < length)
    {
        ssize_t written = 0;
        librdp_status status = x11_managed_ipc_wait(
            descriptor, POLLOUT, timeout_ms, deadline_ms);

        if (status != LIBRDP_STATUS_OK)
            return status;
#ifdef MSG_NOSIGNAL
        written = send(descriptor,
                       data + offset,
                       length - offset,
                       MSG_NOSIGNAL);
#else
        written = send(descriptor, data + offset, length - offset, 0);
#endif
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return LIBRDP_STATUS_IO_ERROR;
        offset += (size_t)written;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_managed_ipc_read_all(
    int descriptor,
    uint8_t* data,
    size_t length,
    int timeout_ms)
{
    uint64_t deadline_ms =
        timeout_ms < 0
            ? 0u
            : x11_managed_ipc_now_ms() + (uint64_t)timeout_ms;
    size_t offset = 0u;

    while (offset < length)
    {
        ssize_t received = 0;
        librdp_status status = x11_managed_ipc_wait(
            descriptor, POLLIN, timeout_ms, deadline_ms);

        if (status != LIBRDP_STATUS_OK)
            return status;
        received = recv(descriptor, data + offset, length - offset, 0);
        if (received < 0 && errno == EINTR)
            continue;
        if (received <= 0)
            return LIBRDP_STATUS_IO_ERROR;
        offset += (size_t)received;
    }
    return LIBRDP_STATUS_OK;
}

static void x11_managed_ipc_write_u16(uint8_t* output, uint16_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8u);
}

static void x11_managed_ipc_write_u32(uint8_t* output, uint32_t value)
{
    size_t index = 0u;

    for (index = 0u; index < 4u; index++)
        output[index] = (uint8_t)(value >> (index * 8u));
}

static void x11_managed_ipc_write_u64(uint8_t* output, uint64_t value)
{
    size_t index = 0u;

    for (index = 0u; index < 8u; index++)
        output[index] = (uint8_t)(value >> (index * 8u));
}

static uint16_t x11_managed_ipc_read_u16(const uint8_t* input)
{
    return (uint16_t)((uint16_t)input[0] | ((uint16_t)input[1] << 8u));
}

static uint32_t x11_managed_ipc_read_u32(const uint8_t* input)
{
    uint32_t value = 0u;
    size_t index = 0u;

    for (index = 0u; index < 4u; index++)
        value |= (uint32_t)input[index] << (index * 8u);
    return value;
}

static uint64_t x11_managed_ipc_read_u64(const uint8_t* input)
{
    uint64_t value = 0u;
    size_t index = 0u;

    for (index = 0u; index < 8u; index++)
        value |= (uint64_t)input[index] << (index * 8u);
    return value;
}

static int x11_managed_ipc_put_u32(
    x11_managed_ipc_cursor* cursor,
    uint32_t value)
{
    if (!cursor || cursor->offset > cursor->capacity ||
        cursor->capacity - cursor->offset < 4u)
        return 0;
    x11_managed_ipc_write_u32(cursor->data + cursor->offset, value);
    cursor->offset += 4u;
    return 1;
}

static int x11_managed_ipc_put_u64(
    x11_managed_ipc_cursor* cursor,
    uint64_t value)
{
    if (!cursor || cursor->offset > cursor->capacity ||
        cursor->capacity - cursor->offset < 8u)
        return 0;
    x11_managed_ipc_write_u64(cursor->data + cursor->offset, value);
    cursor->offset += 8u;
    return 1;
}

static int x11_managed_ipc_get_u32(
    x11_managed_ipc_cursor* cursor,
    uint32_t* value)
{
    if (!cursor || !value || cursor->offset > cursor->capacity ||
        cursor->capacity - cursor->offset < 4u)
        return 0;
    *value = x11_managed_ipc_read_u32(cursor->data + cursor->offset);
    cursor->offset += 4u;
    return 1;
}

static int x11_managed_ipc_get_u64(
    x11_managed_ipc_cursor* cursor,
    uint64_t* value)
{
    if (!cursor || !value || cursor->offset > cursor->capacity ||
        cursor->capacity - cursor->offset < 8u)
        return 0;
    *value = x11_managed_ipc_read_u64(cursor->data + cursor->offset);
    cursor->offset += 8u;
    return 1;
}

static int x11_managed_ipc_string_terminated(
    const char* value,
    size_t capacity)
{
    return value && memchr(value, '\0', capacity) != NULL;
}

static int x11_managed_ipc_put_string(
    x11_managed_ipc_cursor* cursor,
    const char* value,
    size_t capacity)
{
    size_t length = 0u;

    if (!cursor ||
        !x11_managed_ipc_string_terminated(value, capacity))
        return 0;
    length = strlen(value);
    if (length > UINT16_MAX || cursor->offset > cursor->capacity ||
        cursor->capacity - cursor->offset < 2u + length)
        return 0;
    x11_managed_ipc_write_u16(cursor->data + cursor->offset,
                              (uint16_t)length);
    cursor->offset += 2u;
    if (length > 0u)
    {
        memcpy(cursor->data + cursor->offset, value, length);
        cursor->offset += length;
    }
    return 1;
}

static int x11_managed_ipc_get_string(
    x11_managed_ipc_cursor* cursor,
    char* value,
    size_t capacity)
{
    size_t length = 0u;

    if (!cursor || !value || capacity == 0u ||
        cursor->offset > cursor->capacity ||
        cursor->capacity - cursor->offset < 2u)
        return 0;
    length = x11_managed_ipc_read_u16(cursor->data + cursor->offset);
    cursor->offset += 2u;
    if (length >= capacity || cursor->offset > cursor->capacity ||
        cursor->capacity - cursor->offset < length)
        return 0;
    if (length > 0u)
        memcpy(value, cursor->data + cursor->offset, length);
    value[length] = '\0';
    cursor->offset += length;
    return 1;
}

void x11_managed_ipc_message_init(x11_managed_ipc_message* message)
{
    if (!message)
        return;
    memset(message, 0, sizeof(*message));
    message->version = X11_MANAGED_IPC_VERSION;
    message->size = sizeof(*message);
    message->status = LIBRDP_STATUS_OK;
}

void x11_managed_ipc_message_clear(x11_managed_ipc_message* message)
{
    if (!message)
        return;
    OPENSSL_cleanse(message, sizeof(*message));
}

/*
 * Validate both the common envelope and type-specific fields. Optional strings
 * still require in-bounds termination so serialization cannot scan past them.
 */
librdp_status x11_managed_ipc_message_validate(
    const x11_managed_ipc_message* message)
{
    const uint32_t known_flags =
        X11_MANAGED_IPC_ALLOW_INPUT |
        X11_MANAGED_IPC_ALLOW_CLIPBOARD |
        X11_MANAGED_IPC_ALLOW_DRIVE |
        X11_MANAGED_IPC_DRIVE_READ_ONLY |
        X11_MANAGED_IPC_TEST_XVFB |
        X11_MANAGED_IPC_PERSISTENT |
        X11_MANAGED_IPC_RECONNECT |
        X11_MANAGED_IPC_ALLOW_CAPTURE;

    if (!message || message->version != X11_MANAGED_IPC_VERSION ||
        message->size < sizeof(*message) ||
        message->type < X11_MANAGED_IPC_START ||
        message->type > X11_MANAGED_IPC_AUTHENTICATED ||
        message->request_id == 0u ||
        (message->flags & ~known_flags) != 0u ||
        message->status > LIBRDP_STATUS_OK ||
        message->status < LIBRDP_STATUS_CANCELLED ||
        message->port > UINT16_MAX ||
        message->auth_outcome > 5u ||
        message->width > X11_MANAGED_IPC_MAX_DIMENSION ||
        message->height > X11_MANAGED_IPC_MAX_DIMENSION ||
        !x11_managed_ipc_string_terminated(
            message->username, sizeof(message->username)) ||
        !x11_managed_ipc_string_terminated(
            message->domain, sizeof(message->domain)) ||
        !x11_managed_ipc_string_terminated(
            message->password, sizeof(message->password)) ||
        !x11_managed_ipc_string_terminated(
            message->reconnect_token,
            sizeof(message->reconnect_token)) ||
        !x11_managed_ipc_string_terminated(
            message->display_name, sizeof(message->display_name)) ||
        !x11_managed_ipc_string_terminated(
            message->bind_address, sizeof(message->bind_address)) ||
        !x11_managed_ipc_string_terminated(
            message->runtime_directory,
            sizeof(message->runtime_directory)) ||
        !x11_managed_ipc_string_terminated(
            message->control_socket,
            sizeof(message->control_socket)) ||
        !x11_managed_ipc_string_terminated(
            message->desktop_command,
            sizeof(message->desktop_command)) ||
        !x11_managed_ipc_string_terminated(
            message->xserver_command,
            sizeof(message->xserver_command)) ||
        !x11_managed_ipc_string_terminated(
            message->tls_certificate,
            sizeof(message->tls_certificate)) ||
        !x11_managed_ipc_string_terminated(
            message->tls_private_key,
            sizeof(message->tls_private_key)) ||
        !x11_managed_ipc_string_terminated(
            message->drive_mount, sizeof(message->drive_mount)))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (message->type == X11_MANAGED_IPC_START &&
        (message->username[0] == '\0' ||
         message->width == 0u || message->height == 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (message->type == X11_MANAGED_IPC_START &&
        message->session_id != 0u &&
        (message->desktop_command[0] == '\0' ||
         message->xserver_command[0] == '\0' ||
         message->runtime_directory[0] != '/' ||
         message->control_socket[0] != '/'))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((message->type == X11_MANAGED_IPC_ATTACH ||
         (message->flags & X11_MANAGED_IPC_RECONNECT) != 0u) &&
        message->reconnect_token[0] == '\0')
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (message->type == X11_MANAGED_IPC_RESIZE &&
        (message->session_id == 0u ||
         message->width == 0u || message->height == 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if ((message->type == X11_MANAGED_IPC_DETACH ||
         message->type == X11_MANAGED_IPC_TERMINATE ||
         message->type == X11_MANAGED_IPC_QUERY) &&
        message->session_id == 0u &&
        message->reconnect_token[0] == '\0')
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (message->type == X11_MANAGED_IPC_READY &&
        (message->session_id == 0u ||
         message->reconnect_token[0] == '\0' ||
         message->display_name[0] == '\0' ||
         message->port == 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (message->type == X11_MANAGED_IPC_AUTHENTICATED &&
        (message->username[0] == '\0' ||
         message->auth_outcome != 1u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_managed_ipc_encode(
    const x11_managed_ipc_message* message,
    uint8_t* payload,
    size_t capacity,
    size_t* payload_len)
{
    x11_managed_ipc_cursor cursor;

    if (!message || !payload || !payload_len ||
        x11_managed_ipc_message_validate(message) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&cursor, 0, sizeof(cursor));
    cursor.data = payload;
    cursor.capacity = capacity;
    if (!x11_managed_ipc_put_u64(&cursor, message->session_id) ||
        !x11_managed_ipc_put_u64(&cursor, message->created_ns) ||
        !x11_managed_ipc_put_u64(&cursor, message->idle_timeout_ns) ||
        !x11_managed_ipc_put_u64(&cursor, message->max_duration_ns) ||
        !x11_managed_ipc_put_u64(&cursor, message->supervisor_pid) ||
        !x11_managed_ipc_put_u64(&cursor, message->agent_pid) ||
        !x11_managed_ipc_put_u64(&cursor, message->xserver_pid) ||
        !x11_managed_ipc_put_u64(&cursor, message->desktop_pid) ||
        !x11_managed_ipc_put_u32(&cursor, message->flags) ||
        !x11_managed_ipc_put_u32(&cursor, message->uid) ||
        !x11_managed_ipc_put_u32(&cursor, message->gid) ||
        !x11_managed_ipc_put_u32(&cursor, message->width) ||
        !x11_managed_ipc_put_u32(&cursor, message->height) ||
        !x11_managed_ipc_put_u32(&cursor, message->port) ||
        !x11_managed_ipc_put_u32(&cursor, message->security_mode) ||
        !x11_managed_ipc_put_u32(&cursor, message->max_peers) ||
        !x11_managed_ipc_put_u32(&cursor, message->auth_outcome) ||
        !x11_managed_ipc_put_u32(&cursor, (uint32_t)message->status) ||
        !x11_managed_ipc_put_string(
            &cursor, message->username, sizeof(message->username)) ||
        !x11_managed_ipc_put_string(
            &cursor, message->domain, sizeof(message->domain)) ||
        !x11_managed_ipc_put_string(
            &cursor, message->password, sizeof(message->password)) ||
        !x11_managed_ipc_put_string(
            &cursor,
            message->reconnect_token,
            sizeof(message->reconnect_token)) ||
        !x11_managed_ipc_put_string(
            &cursor,
            message->display_name,
            sizeof(message->display_name)) ||
        !x11_managed_ipc_put_string(
            &cursor,
            message->bind_address,
            sizeof(message->bind_address)) ||
        !x11_managed_ipc_put_string(
            &cursor,
            message->runtime_directory,
            sizeof(message->runtime_directory)) ||
        !x11_managed_ipc_put_string(
            &cursor,
            message->control_socket,
            sizeof(message->control_socket)) ||
        !x11_managed_ipc_put_string(
            &cursor,
            message->desktop_command,
            sizeof(message->desktop_command)) ||
        !x11_managed_ipc_put_string(
            &cursor,
            message->xserver_command,
            sizeof(message->xserver_command)) ||
        !x11_managed_ipc_put_string(
            &cursor,
            message->tls_certificate,
            sizeof(message->tls_certificate)) ||
        !x11_managed_ipc_put_string(
            &cursor,
            message->tls_private_key,
            sizeof(message->tls_private_key)) ||
        !x11_managed_ipc_put_string(
            &cursor, message->drive_mount, sizeof(message->drive_mount)))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    *payload_len = cursor.offset;
    return LIBRDP_STATUS_OK;
}

static librdp_status x11_managed_ipc_decode(
    const uint8_t* payload,
    size_t payload_len,
    x11_managed_ipc_message* message)
{
    x11_managed_ipc_cursor cursor;
    uint32_t status_value = 0u;

    if (!payload || !message)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&cursor, 0, sizeof(cursor));
    cursor.data = (uint8_t*)payload;
    cursor.capacity = payload_len;
    if (!x11_managed_ipc_get_u64(&cursor, &message->session_id) ||
        !x11_managed_ipc_get_u64(&cursor, &message->created_ns) ||
        !x11_managed_ipc_get_u64(&cursor, &message->idle_timeout_ns) ||
        !x11_managed_ipc_get_u64(&cursor, &message->max_duration_ns) ||
        !x11_managed_ipc_get_u64(&cursor, &message->supervisor_pid) ||
        !x11_managed_ipc_get_u64(&cursor, &message->agent_pid) ||
        !x11_managed_ipc_get_u64(&cursor, &message->xserver_pid) ||
        !x11_managed_ipc_get_u64(&cursor, &message->desktop_pid) ||
        !x11_managed_ipc_get_u32(&cursor, &message->flags) ||
        !x11_managed_ipc_get_u32(&cursor, &message->uid) ||
        !x11_managed_ipc_get_u32(&cursor, &message->gid) ||
        !x11_managed_ipc_get_u32(&cursor, &message->width) ||
        !x11_managed_ipc_get_u32(&cursor, &message->height) ||
        !x11_managed_ipc_get_u32(&cursor, &message->port) ||
        !x11_managed_ipc_get_u32(&cursor, &message->security_mode) ||
        !x11_managed_ipc_get_u32(&cursor, &message->max_peers) ||
        !x11_managed_ipc_get_u32(&cursor, &message->auth_outcome) ||
        !x11_managed_ipc_get_u32(&cursor, &status_value) ||
        !x11_managed_ipc_get_string(
            &cursor, message->username, sizeof(message->username)) ||
        !x11_managed_ipc_get_string(
            &cursor, message->domain, sizeof(message->domain)) ||
        !x11_managed_ipc_get_string(
            &cursor, message->password, sizeof(message->password)) ||
        !x11_managed_ipc_get_string(
            &cursor,
            message->reconnect_token,
            sizeof(message->reconnect_token)) ||
        !x11_managed_ipc_get_string(
            &cursor,
            message->display_name,
            sizeof(message->display_name)) ||
        !x11_managed_ipc_get_string(
            &cursor,
            message->bind_address,
            sizeof(message->bind_address)) ||
        !x11_managed_ipc_get_string(
            &cursor,
            message->runtime_directory,
            sizeof(message->runtime_directory)) ||
        !x11_managed_ipc_get_string(
            &cursor,
            message->control_socket,
            sizeof(message->control_socket)) ||
        !x11_managed_ipc_get_string(
            &cursor,
            message->desktop_command,
            sizeof(message->desktop_command)) ||
        !x11_managed_ipc_get_string(
            &cursor,
            message->xserver_command,
            sizeof(message->xserver_command)) ||
        !x11_managed_ipc_get_string(
            &cursor,
            message->tls_certificate,
            sizeof(message->tls_certificate)) ||
        !x11_managed_ipc_get_string(
            &cursor,
            message->tls_private_key,
            sizeof(message->tls_private_key)) ||
        !x11_managed_ipc_get_string(
            &cursor, message->drive_mount, sizeof(message->drive_mount)) ||
        cursor.offset != payload_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    message->status = (librdp_status)status_value;
    return x11_managed_ipc_message_validate(message);
}

librdp_status x11_managed_ipc_send(
    int descriptor,
    const x11_managed_ipc_message* message,
    int timeout_ms)
{
    uint8_t frame[X11_MANAGED_IPC_MAX_FRAME_BYTES];
    size_t payload_len = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (descriptor < 0 || timeout_ms < -1)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = x11_managed_ipc_encode(
        message,
        frame + X11_MANAGED_IPC_HEADER_BYTES,
        sizeof(frame) - X11_MANAGED_IPC_HEADER_BYTES,
        &payload_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    x11_managed_ipc_write_u32(frame, X11_MANAGED_IPC_MAGIC);
    x11_managed_ipc_write_u16(
        frame + 4u, (uint16_t)X11_MANAGED_IPC_VERSION);
    x11_managed_ipc_write_u16(
        frame + 6u, (uint16_t)message->type);
    x11_managed_ipc_write_u32(frame + 8u, (uint32_t)payload_len);
    x11_managed_ipc_write_u64(frame + 12u, message->request_id);
    x11_managed_ipc_write_u32(frame + 20u, 0u);
    status = x11_managed_ipc_write_all(
        descriptor,
        frame,
        X11_MANAGED_IPC_HEADER_BYTES + payload_len,
        timeout_ms);
    OPENSSL_cleanse(frame, sizeof(frame));
    return status;
}

librdp_status x11_managed_ipc_receive(
    int descriptor,
    x11_managed_ipc_message* message,
    int timeout_ms)
{
    uint8_t frame[X11_MANAGED_IPC_MAX_FRAME_BYTES];
    uint32_t payload_len = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (descriptor < 0 || !message || timeout_ms < -1)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    x11_managed_ipc_message_clear(message);
    x11_managed_ipc_message_init(message);
    status = x11_managed_ipc_read_all(
        descriptor, frame, X11_MANAGED_IPC_HEADER_BYTES, timeout_ms);
    if (status != LIBRDP_STATUS_OK)
        return status;
    payload_len = x11_managed_ipc_read_u32(frame + 8u);
    if (x11_managed_ipc_read_u32(frame) != X11_MANAGED_IPC_MAGIC ||
        x11_managed_ipc_read_u16(frame + 4u) !=
            X11_MANAGED_IPC_VERSION ||
        x11_managed_ipc_read_u16(frame + 6u) <
            X11_MANAGED_IPC_START ||
        x11_managed_ipc_read_u16(frame + 6u) >
            X11_MANAGED_IPC_AUTHENTICATED ||
        x11_managed_ipc_read_u32(frame + 20u) != 0u ||
        payload_len == 0u ||
        payload_len >
            X11_MANAGED_IPC_MAX_FRAME_BYTES -
                X11_MANAGED_IPC_HEADER_BYTES)
    {
        OPENSSL_cleanse(frame, sizeof(frame));
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    message->type =
        (x11_managed_ipc_type)x11_managed_ipc_read_u16(frame + 6u);
    message->request_id = x11_managed_ipc_read_u64(frame + 12u);
    status = x11_managed_ipc_read_all(
        descriptor,
        frame + X11_MANAGED_IPC_HEADER_BYTES,
        payload_len,
        timeout_ms);
    if (status == LIBRDP_STATUS_OK)
    {
        status = x11_managed_ipc_decode(
            frame + X11_MANAGED_IPC_HEADER_BYTES,
            payload_len,
            message);
    }
    if (status != LIBRDP_STATUS_OK)
    {
        x11_managed_ipc_message_clear(message);
        x11_managed_ipc_message_init(message);
    }
    OPENSSL_cleanse(frame, sizeof(frame));
    return status;
}

librdp_status x11_managed_ipc_peer_identity(
    int descriptor,
    x11_managed_ipc_identity* identity)
{
    if (descriptor < 0 || !identity)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(identity, 0, sizeof(*identity));
#if defined(__linux__)
    {
        struct ucred credentials;
        socklen_t length = sizeof(credentials);

        memset(&credentials, 0, sizeof(credentials));
        if (getsockopt(descriptor,
                       SOL_SOCKET,
                       SO_PEERCRED,
                       &credentials,
                       &length) != 0 ||
            length != sizeof(credentials))
            return LIBRDP_STATUS_IO_ERROR;
        identity->uid = credentials.uid;
        identity->gid = credentials.gid;
        identity->pid = credentials.pid;
    }
#elif defined(__sun)
    {
        ucred_t* credentials = NULL;

        if (getpeerucred(descriptor, &credentials) != 0 || !credentials)
            return LIBRDP_STATUS_IO_ERROR;
        identity->uid = ucred_geteuid(credentials);
        identity->gid = ucred_getegid(credentials);
        identity->pid = ucred_getpid(credentials);
        ucred_free(credentials);
    }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__)
    if (getpeereid(descriptor, &identity->uid, &identity->gid) != 0)
        return LIBRDP_STATUS_IO_ERROR;
#else
    return LIBRDP_STATUS_UNSUPPORTED;
#endif
    return LIBRDP_STATUS_OK;
}

librdp_status x11_managed_ipc_generate_token(
    char token[X11_MANAGED_IPC_TOKEN_BYTES])
{
    static const char hex[] = "0123456789abcdef";
    uint8_t bytes[32];
    size_t index = 0u;

    if (!token)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (RAND_bytes(bytes, (int)sizeof(bytes)) != 1)
        return LIBRDP_STATUS_IO_ERROR;
    for (index = 0u; index < sizeof(bytes); index++)
    {
        token[index * 2u] = hex[bytes[index] >> 4u];
        token[index * 2u + 1u] = hex[bytes[index] & 0x0fu];
    }
    token[sizeof(bytes) * 2u] = '\0';
    OPENSSL_cleanse(bytes, sizeof(bytes));
    return LIBRDP_STATUS_OK;
}

int x11_managed_ipc_token_equal(const char* left, const char* right)
{
    size_t left_len = left ? strnlen(left, X11_MANAGED_IPC_TOKEN_BYTES) : 0u;
    size_t right_len =
        right ? strnlen(right, X11_MANAGED_IPC_TOKEN_BYTES) : 0u;

    if (left_len != X11_MANAGED_IPC_TOKEN_BYTES - 1u ||
        right_len != X11_MANAGED_IPC_TOKEN_BYTES - 1u)
        return 0;
    return CRYPTO_memcmp(left,
                         right,
                         X11_MANAGED_IPC_TOKEN_BYTES - 1u) == 0;
}
