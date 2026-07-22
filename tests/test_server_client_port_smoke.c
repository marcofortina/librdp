/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: end-to-end client port-redirection smoke tests.
 * Coverage: public client/server activation and RDPDR device negotiation with
 * host-backed serial and parallel descriptors.
 * Bug classes: device-family gating, malformed IRP correlation, termios state
 * drift, partial I/O loss, timeout handling, cancellation and unplug cleanup.
 * Determinism: transport remains on loopback and serial I/O uses a private PTY.
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "channels/device_redirection.h"
#include "channels/filesystem_redirection.h"
#include "channels/port_redirection.h"

#include <librdp/librdp.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define PORT_SMOKE_WIDTH LIBRDP_DESKTOP_MIN_DIMENSION
#define PORT_SMOKE_HEIGHT LIBRDP_DESKTOP_MIN_DIMENSION
#define PORT_SMOKE_PUMP_LIMIT 800u
#define PORT_SMOKE_WRITE_BYTES (1024u * 1024u)
#define PORT_SMOKE_BAUD_RATE 19200u
#define PORT_SMOKE_IO_SUCCESS 0x00000000u
#define PORT_SMOKE_IO_NOT_SUPPORTED 0xc00000bbu
#define PORT_SMOKE_PURGE_RX_ABORT 0x00000002u
#define PORT_SMOKE_PURGE_TX_ABORT 0x00000001u
#define PORT_SMOKE_UNKNOWN_CONTROL 0x0016fffcu

static const uint8_t port_smoke_serial_input[] = {
    0x52u, 0x58u, 0x2du, 0x31u, 0x37u,
};

static const uint8_t port_smoke_parallel_output[] = {
    0x50u, 0x41u, 0x52u, 0x41u, 0x4cu, 0x4cu, 0x45u, 0x4cu,
};

typedef enum port_smoke_stage
{
    PORT_SMOKE_WAIT_DEVICE = 0,
    PORT_SMOKE_WAIT_CREATE = 1,
    PORT_SMOKE_WAIT_SET_BAUD = 2,
    PORT_SMOKE_WAIT_GET_BAUD = 3,
    PORT_SMOKE_WAIT_SET_LINE = 4,
    PORT_SMOKE_WAIT_GET_LINE = 5,
    PORT_SMOKE_WAIT_SET_TIMEOUTS = 6,
    PORT_SMOKE_WAIT_GET_TIMEOUTS = 7,
    PORT_SMOKE_WAIT_MODEM_STATUS = 8,
    PORT_SMOKE_WAIT_PARTIAL_READ = 9,
    PORT_SMOKE_WAIT_PARTIAL_WRITE = 10,
    PORT_SMOKE_WAIT_TIMEOUT_READ = 11,
    PORT_SMOKE_WAIT_PURGE_CANCEL = 12,
    PORT_SMOKE_WAIT_UNPLUG_WRITE = 13,
    PORT_SMOKE_WAIT_CLOSE = 14,
    PORT_SMOKE_COMPLETE = 15,
    PORT_SMOKE_WAIT_PARALLEL_DEVICE = 16,
    PORT_SMOKE_WAIT_PARALLEL_CREATE = 17,
    PORT_SMOKE_WAIT_PARALLEL_WRITE = 18,
    PORT_SMOKE_WAIT_PARALLEL_STATUS = 19,
    PORT_SMOKE_WAIT_PARALLEL_UNSUPPORTED = 20,
    PORT_SMOKE_WAIT_PARALLEL_CLOSE = 21,
    PORT_SMOKE_PARALLEL_COMPLETE = 22,
    PORT_SMOKE_FAILED = 23
} port_smoke_stage;

typedef struct port_smoke_fixture
{
    librdp_server_config config;
    pthread_t thread;
    atomic_uint port;
    atomic_uint stop;
    atomic_uint stage;
    atomic_uint completions;
    atomic_uint active_events;
    atomic_uint client_errors;
    atomic_uint trace_errors;
    uint16_t channel_id;
    uint32_t device_id;
    uint32_t file_id;
    uint32_t next_completion_id;
    uint32_t expected_completion_id;
    uint32_t timeout_values[5];
    librdp_server_extension_family extension_family;
    uint32_t device_type;
    int master_fd;
    int slave_fd;
    char slave_path[256];
    uint8_t* write_data;
    size_t write_data_len;
    size_t partial_written;
    librdp_status status;
    librdp_status failure_status;
    uint32_t failure_io_status;
} port_smoke_fixture;

static int port_smoke_check(int condition,
                            const char* expression,
                            int line)
{
    if (condition)
        return 0;
    fprintf(stderr,
            "test_server_client_port_smoke:%d: check failed: %s\n",
            line,
            expression);
    return 1;
}

#define REQUIRE(expression)                                            \
    do                                                                 \
    {                                                                  \
        if (port_smoke_check((expression), #expression, __LINE__) != 0) \
        {                                                              \
            result = 1;                                                \
            goto cleanup;                                              \
        }                                                              \
    } while (0)

static uint32_t port_smoke_read_u32_le(const uint8_t* data)
{
    if (!data)
        return 0u;
    return (uint32_t)data[0] |
           ((uint32_t)data[1] << 8u) |
           ((uint32_t)data[2] << 16u) |
           ((uint32_t)data[3] << 24u);
}

static void port_smoke_write_u32_le(uint8_t* data, uint32_t value)
{
    if (!data)
        return;
    data[0] = (uint8_t)(value & 0xffu);
    data[1] = (uint8_t)((value >> 8u) & 0xffu);
    data[2] = (uint8_t)((value >> 16u) & 0xffu);
    data[3] = (uint8_t)((value >> 24u) & 0xffu);
}

static uint8_t port_smoke_pattern(size_t offset)
{
    return (uint8_t)(((offset * 31u) + 7u) & 0xffu);
}

static void port_smoke_fail(port_smoke_fixture* fixture,
                            librdp_status status,
                            uint32_t io_status)
{
    if (!fixture)
        return;
    fixture->failure_status = status;
    fixture->failure_io_status = io_status;
    atomic_store_explicit(&fixture->stage,
                          PORT_SMOKE_FAILED,
                          memory_order_release);
}

static int port_smoke_stage_complete(port_smoke_stage stage)
{
    return stage == PORT_SMOKE_COMPLETE ||
           stage == PORT_SMOKE_PARALLEL_COMPLETE;
}

static int port_smoke_pty_error(const char* operation)
{
    int saved_errno = errno;

    fprintf(stderr,
            "PTY fixture failed operation=%s errno=%d message=%s\n",
            operation ? operation : "unknown",
            saved_errno,
            strerror(saved_errno));
    return 0;
}

static int port_smoke_prepare_pty(port_smoke_fixture* fixture)
{
    struct termios terminal;
    const char* name = NULL;
    int flags = 0;

    if (!fixture)
        return 0;
    fixture->master_fd =
        posix_openpt(O_RDWR | O_NOCTTY);
    if (fixture->master_fd < 0)
        return port_smoke_pty_error("posix_openpt");
    if (grantpt(fixture->master_fd) != 0)
        return port_smoke_pty_error("grantpt");
    if (unlockpt(fixture->master_fd) != 0)
        return port_smoke_pty_error("unlockpt");
    name = ptsname(fixture->master_fd);
    if (!name)
        return port_smoke_pty_error("ptsname");
    if (snprintf(fixture->slave_path,
                 sizeof(fixture->slave_path),
                 "%s",
                 name) <= 0)
    {
        errno = EINVAL;
        return port_smoke_pty_error("slave-path");
    }
    fixture->slave_fd = open(fixture->slave_path,
                             O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fixture->slave_fd < 0)
        return port_smoke_pty_error("open-slave");
    if (tcgetattr(fixture->slave_fd, &terminal) != 0)
    {
        int saved_errno = errno;

        close(fixture->slave_fd);
        fixture->slave_fd = -1;
        errno = saved_errno;
        return port_smoke_pty_error("tcgetattr");
    }
    terminal.c_iflag &=
        (tcflag_t)~(tcflag_t)(IGNBRK | BRKINT | PARMRK | ISTRIP |
                             INLCR | IGNCR | ICRNL | IXON);
    terminal.c_oflag &= (tcflag_t)~(tcflag_t)OPOST;
    terminal.c_cflag &= (tcflag_t)~(tcflag_t)(CSIZE | PARENB);
    terminal.c_cflag |= (tcflag_t)(CS8 | CLOCAL | CREAD);
    terminal.c_lflag &=
        (tcflag_t)~(tcflag_t)(ECHO | ECHONL | ICANON | IEXTEN | ISIG);
    terminal.c_cc[VMIN] = 0;
    terminal.c_cc[VTIME] = 0;
    if (tcsetattr(fixture->slave_fd, TCSANOW, &terminal) != 0)
    {
        int saved_errno = errno;

        close(fixture->slave_fd);
        fixture->slave_fd = -1;
        errno = saved_errno;
        return port_smoke_pty_error("tcsetattr");
    }
    flags = fcntl(fixture->master_fd, F_GETFL, 0);
    if (flags < 0)
        return port_smoke_pty_error("fcntl-getfl");
    if (fcntl(fixture->master_fd,
              F_SETFL,
              flags | O_NONBLOCK) != 0)
        return port_smoke_pty_error("fcntl-setfl");
    flags = fcntl(fixture->master_fd, F_GETFD, 0);
    if (flags < 0)
        return port_smoke_pty_error("fcntl-getfd");
    if (fcntl(fixture->master_fd,
              F_SETFD,
              flags | FD_CLOEXEC) != 0)
        return port_smoke_pty_error("fcntl-setfd");
    return 1;
}

static int port_smoke_prepare_parallel_file(
    port_smoke_fixture* fixture)
{
    const char* temp_directory = NULL;
    int flags = 0;
    int length = 0;

    if (!fixture)
        return 0;
    temp_directory = getenv("TMPDIR");
    if (!temp_directory || temp_directory[0] == '\0')
        temp_directory = "/tmp";
    length = snprintf(fixture->slave_path,
                      sizeof(fixture->slave_path),
                      "%s/librdp-parallel-XXXXXX",
                      temp_directory);
    if (length <= 0 ||
        (size_t)length >= sizeof(fixture->slave_path))
        return 0;
    fixture->master_fd = mkstemp(fixture->slave_path);
    if (fixture->master_fd < 0)
        return 0;
    flags = fcntl(fixture->master_fd, F_GETFD, 0);
    return flags >= 0 &&
           fcntl(fixture->master_fd,
                 F_SETFD,
                 flags | FD_CLOEXEC) == 0;
}

/*
 * Wait until the PTY line discipline has published master-side input to the
 * slave queue. Polling a separate descriptor observes readiness without
 * consuming bytes intended for the redirected port.
 */
static int port_smoke_wait_serial_input(
    const port_smoke_fixture* fixture)
{
    struct pollfd descriptor;
    int ready = 0;

    if (!fixture || fixture->slave_fd < 0)
        return 0;
    descriptor.fd = fixture->slave_fd;
    descriptor.events = POLLIN;
    descriptor.revents = 0;
    do
    {
        ready = poll(&descriptor, 1u, 1000);
    } while (ready < 0 && errno == EINTR);
    return ready > 0 &&
           (descriptor.revents & POLLIN) != 0;
}

static int port_smoke_wait_for_port(const atomic_uint* source,
                                    uint16_t* port)
{
    const struct timespec delay = {0, 10000000L};

    if (!source || !port)
        return 0;
    for (unsigned int attempt = 0u;
         attempt < PORT_SMOKE_PUMP_LIMIT;
         attempt++)
    {
        unsigned int value =
            atomic_load_explicit(source, memory_order_acquire);

        if (value > 0u && value <= UINT16_MAX)
        {
            *port = (uint16_t)value;
            return 1;
        }
        (void)nanosleep(&delay, NULL);
    }
    return 0;
}

static librdp_status port_smoke_send_packet(
    port_smoke_fixture* fixture,
    librdp_server_peer* peer,
    port_smoke_stage stage,
    rdp_buffer* packet)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!fixture || !peer || !packet || packet->length == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    atomic_store_explicit(&fixture->stage,
                          (unsigned int)stage,
                          memory_order_release);
    status = librdp_server_peer_send_static_extension_data(
        peer,
        fixture->extension_family,
        fixture->channel_id,
        packet->data,
        packet->length);
    if (status != LIBRDP_STATUS_OK)
        port_smoke_fail(fixture, status, 0u);
    return status;
}

static uint32_t port_smoke_next_completion(
    port_smoke_fixture* fixture)
{
    if (!fixture)
        return 0u;
    fixture->next_completion_id++;
    if (fixture->next_completion_id == 0u)
        fixture->next_completion_id++;
    fixture->expected_completion_id =
        fixture->next_completion_id;
    return fixture->expected_completion_id;
}

static librdp_status port_smoke_send_create(
    port_smoke_fixture* fixture,
    librdp_server_peer* peer)
{
    static const uint8_t empty_path[2] = {0u, 0u};
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&packet);
    status = rdp_filesystem_redirection_write_create_request(
        &packet,
        fixture->device_id,
        0u,
        port_smoke_next_completion(fixture),
        0u,
        0u,
        0u,
        0u,
        1u,
        0u,
        empty_path,
        sizeof(empty_path));
    if (status == LIBRDP_STATUS_OK)
    {
        status = port_smoke_send_packet(fixture,
                                        peer,
                                        fixture->extension_family ==
                                                LIBRDP_SERVER_EXTENSION_SERIAL_PORT
                                            ? PORT_SMOKE_WAIT_CREATE
                                            : PORT_SMOKE_WAIT_PARALLEL_CREATE,
                                        &packet);
    }
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status port_smoke_send_control(
    port_smoke_fixture* fixture,
    librdp_server_peer* peer,
    port_smoke_stage stage,
    uint32_t output_length,
    uint32_t control_code,
    const void* input,
    uint32_t input_len)
{
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&packet);
    status = rdp_port_redirection_write_control_request(
        &packet,
        fixture->device_id,
        fixture->file_id,
        port_smoke_next_completion(fixture),
        output_length,
        control_code,
        input,
        input_len);
    if (status == LIBRDP_STATUS_OK)
        status = port_smoke_send_packet(fixture, peer, stage, &packet);
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status port_smoke_send_read(
    port_smoke_fixture* fixture,
    librdp_server_peer* peer,
    port_smoke_stage stage,
    uint32_t length)
{
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&packet);
    status = rdp_filesystem_redirection_write_read_request(
        &packet,
        fixture->device_id,
        fixture->file_id,
        port_smoke_next_completion(fixture),
        length,
        0u);
    if (status == LIBRDP_STATUS_OK)
        status = port_smoke_send_packet(fixture, peer, stage, &packet);
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status port_smoke_send_write(
    port_smoke_fixture* fixture,
    librdp_server_peer* peer,
    port_smoke_stage stage,
    const void* data,
    uint32_t data_len)
{
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&packet);
    status = rdp_filesystem_redirection_write_write_request(
        &packet,
        fixture->device_id,
        fixture->file_id,
        port_smoke_next_completion(fixture),
        0u,
        data,
        data_len);
    if (status == LIBRDP_STATUS_OK)
        status = port_smoke_send_packet(fixture, peer, stage, &packet);
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status port_smoke_send_close(
    port_smoke_fixture* fixture,
    librdp_server_peer* peer,
    port_smoke_stage stage)
{
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&packet);
    status = rdp_filesystem_redirection_write_close_request(
        &packet,
        fixture->device_id,
        fixture->file_id,
        port_smoke_next_completion(fixture));
    if (status == LIBRDP_STATUS_OK)
    {
        status = port_smoke_send_packet(fixture,
                                        peer,
                                        stage,
                                        &packet);
    }
    rdp_buffer_free(&packet);
    return status;
}

static int port_smoke_length_response(
    const librdp_server_extension_event* event,
    port_smoke_fixture* fixture,
    rdp_filesystem_redirection_length_response* response)
{
    if (!event || !fixture || !response)
        return 0;
    if (rdp_filesystem_redirection_parse_length_response(
            event->payload, event->payload_len, response) !=
            LIBRDP_STATUS_OK &&
        rdp_filesystem_redirection_parse_write_response(
            event->payload, event->payload_len, response) !=
            LIBRDP_STATUS_OK)
        return 0;
    if (response->io.device_id != fixture->device_id ||
        response->io.completion_id !=
            fixture->expected_completion_id)
        return 0;
    return 1;
}

static int port_smoke_drain_master(port_smoke_fixture* fixture,
                                   size_t expected)
{
    uint8_t buffer[4096];
    size_t total = 0u;

    if (!fixture || fixture->master_fd < 0)
        return 0;
    while (total < expected)
    {
        size_t wanted = expected - total;
        ssize_t count = 0;

        if (wanted > sizeof(buffer))
            wanted = sizeof(buffer);
        count = read(fixture->master_fd, buffer, wanted);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
        if (count <= 0)
            return 0;
        for (ssize_t index = 0; index < count; index++)
        {
            if (buffer[index] !=
                port_smoke_pattern(total + (size_t)index))
                return 0;
        }
        total += (size_t)count;
    }
    return total == expected;
}

static int port_smoke_verify_parallel_output(
    const port_smoke_fixture* fixture)
{
    uint8_t output[sizeof(port_smoke_parallel_output)];
    ssize_t count = 0;

    if (!fixture || fixture->master_fd < 0)
        return 0;
    do
    {
        count = pread(fixture->master_fd,
                      output,
                      sizeof(output),
                      0);
    } while (count < 0 && errno == EINTR);
    return count == (ssize_t)sizeof(output) &&
           memcmp(output,
                  port_smoke_parallel_output,
                  sizeof(output)) == 0;
}

/*
 * Advance the serial transaction only after strict completion correlation and
 * payload checks. Every request traverses the live static channel; local PTY
 * checks independently verify bytes that crossed the redirector.
 */
static void port_smoke_handle_completion(
    port_smoke_fixture* fixture,
    librdp_server_peer* peer,
    const librdp_server_extension_event* event)
{
    rdp_filesystem_redirection_length_response length_response;
    port_smoke_stage stage = PORT_SMOKE_FAILED;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!fixture || !peer || !event)
        return;
    stage = (port_smoke_stage)atomic_load_explicit(
        &fixture->stage,
        memory_order_acquire);
    atomic_fetch_add_explicit(&fixture->completions,
                              1u,
                              memory_order_relaxed);
    memset(&length_response, 0, sizeof(length_response));

    if (stage == PORT_SMOKE_WAIT_CREATE)
    {
        rdp_filesystem_redirection_create_response response;
        uint8_t baud[4];

        if (rdp_filesystem_redirection_parse_create_response(
                event->payload,
                event->payload_len,
                &response) != LIBRDP_STATUS_OK ||
            response.io.device_id != fixture->device_id ||
            response.io.completion_id !=
                fixture->expected_completion_id ||
            response.io.io_status != PORT_SMOKE_IO_SUCCESS ||
            response.file_id == 0u)
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            response.io.io_status);
            return;
        }
        fixture->file_id = response.file_id;
        port_smoke_write_u32_le(baud, PORT_SMOKE_BAUD_RATE);
        status = port_smoke_send_control(
            fixture,
            peer,
            PORT_SMOKE_WAIT_SET_BAUD,
            0u,
            RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_BAUD_RATE,
            baud,
            sizeof(baud));
    }
    else if (stage == PORT_SMOKE_WAIT_SET_BAUD)
    {
        if (!port_smoke_length_response(
                event,
                fixture,
                &length_response) ||
            length_response.io.io_status != PORT_SMOKE_IO_SUCCESS ||
            length_response.length != 0u)
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            length_response.io.io_status);
            return;
        }
        status = port_smoke_send_control(
            fixture,
            peer,
            PORT_SMOKE_WAIT_GET_BAUD,
            4u,
            RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_BAUD_RATE,
            NULL,
            0u);
    }
    else if (stage == PORT_SMOKE_WAIT_GET_BAUD)
    {
        static const uint8_t line_control[3] = {0u, 0u, 8u};

        if (!port_smoke_length_response(
                event,
                fixture,
                &length_response) ||
            length_response.io.io_status != PORT_SMOKE_IO_SUCCESS ||
            length_response.length != 4u ||
            port_smoke_read_u32_le(length_response.buffer) !=
                PORT_SMOKE_BAUD_RATE)
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            length_response.io.io_status);
            return;
        }
        status = port_smoke_send_control(
            fixture,
            peer,
            PORT_SMOKE_WAIT_SET_LINE,
            0u,
            RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_LINE_CONTROL,
            line_control,
            sizeof(line_control));
    }
    else if (stage == PORT_SMOKE_WAIT_SET_LINE)
    {
        if (!port_smoke_length_response(
                event,
                fixture,
                &length_response) ||
            length_response.io.io_status != PORT_SMOKE_IO_SUCCESS ||
            length_response.length != 0u)
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            length_response.io.io_status);
            return;
        }
        status = port_smoke_send_control(
            fixture,
            peer,
            PORT_SMOKE_WAIT_GET_LINE,
            3u,
            RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_LINE_CONTROL,
            NULL,
            0u);
    }
    else if (stage == PORT_SMOKE_WAIT_GET_LINE)
    {
        static const uint8_t expected[3] = {0u, 0u, 8u};
        uint8_t timeouts[20];

        if (!port_smoke_length_response(
                event,
                fixture,
                &length_response) ||
            length_response.io.io_status != PORT_SMOKE_IO_SUCCESS ||
            length_response.length != sizeof(expected) ||
            memcmp(length_response.buffer,
                   expected,
                   sizeof(expected)) != 0)
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            length_response.io.io_status);
            return;
        }
        for (size_t index = 0u; index < 5u; index++)
        {
            port_smoke_write_u32_le(
                timeouts + index * 4u,
                fixture->timeout_values[index]);
        }
        status = port_smoke_send_control(
            fixture,
            peer,
            PORT_SMOKE_WAIT_SET_TIMEOUTS,
            0u,
            RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_TIMEOUTS,
            timeouts,
            sizeof(timeouts));
    }
    else if (stage == PORT_SMOKE_WAIT_SET_TIMEOUTS)
    {
        if (!port_smoke_length_response(
                event,
                fixture,
                &length_response) ||
            length_response.io.io_status != PORT_SMOKE_IO_SUCCESS ||
            length_response.length != 0u)
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            length_response.io.io_status);
            return;
        }
        status = port_smoke_send_control(
            fixture,
            peer,
            PORT_SMOKE_WAIT_GET_TIMEOUTS,
            20u,
            RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_TIMEOUTS,
            NULL,
            0u);
    }
    else if (stage == PORT_SMOKE_WAIT_GET_TIMEOUTS)
    {
        int valid = port_smoke_length_response(
            event,
            fixture,
            &length_response);

        if (valid &&
            length_response.io.io_status == PORT_SMOKE_IO_SUCCESS &&
            length_response.length == 20u)
        {
            for (size_t index = 0u; index < 5u; index++)
            {
                if (port_smoke_read_u32_le(
                        length_response.buffer + index * 4u) !=
                    fixture->timeout_values[index])
                    valid = 0;
            }
        }
        else
            valid = 0;
        if (!valid)
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            length_response.io.io_status);
            return;
        }
        status = port_smoke_send_control(
            fixture,
            peer,
            PORT_SMOKE_WAIT_MODEM_STATUS,
            4u,
            RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_MODEMSTATUS,
            NULL,
            0u);
    }
    else if (stage == PORT_SMOKE_WAIT_MODEM_STATUS)
    {
        ssize_t count = 0;

        if (!port_smoke_length_response(
                event,
                fixture,
                &length_response) ||
            length_response.io.io_status != PORT_SMOKE_IO_SUCCESS ||
            length_response.length != 4u)
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            length_response.io.io_status);
            return;
        }
        count = write(fixture->master_fd,
                      port_smoke_serial_input,
                      sizeof(port_smoke_serial_input));
        if (count != (ssize_t)sizeof(port_smoke_serial_input) ||
            !port_smoke_wait_serial_input(fixture))
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_IO_ERROR,
                            0u);
            return;
        }
        status = port_smoke_send_read(
            fixture,
            peer,
            PORT_SMOKE_WAIT_PARTIAL_READ,
            32u);
    }
    else if (stage == PORT_SMOKE_WAIT_PARTIAL_READ)
    {
        if (!port_smoke_length_response(
                event,
                fixture,
                &length_response) ||
            length_response.io.io_status != PORT_SMOKE_IO_SUCCESS ||
            length_response.length !=
                sizeof(port_smoke_serial_input) ||
            memcmp(length_response.buffer,
                   port_smoke_serial_input,
                   sizeof(port_smoke_serial_input)) != 0)
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            length_response.io.io_status);
            return;
        }
        status = port_smoke_send_write(
            fixture,
            peer,
            PORT_SMOKE_WAIT_PARTIAL_WRITE,
            fixture->write_data,
            (uint32_t)fixture->write_data_len);
    }
    else if (stage == PORT_SMOKE_WAIT_PARTIAL_WRITE)
    {
        if (!port_smoke_length_response(
                event,
                fixture,
                &length_response) ||
            length_response.io.io_status != PORT_SMOKE_IO_SUCCESS ||
            length_response.length == 0u ||
            length_response.length >= fixture->write_data_len ||
            !port_smoke_drain_master(fixture,
                                     length_response.length))
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            length_response.io.io_status);
            return;
        }
        fixture->partial_written = length_response.length;
        status = port_smoke_send_read(
            fixture,
            peer,
            PORT_SMOKE_WAIT_TIMEOUT_READ,
            8u);
    }
    else if (stage == PORT_SMOKE_WAIT_TIMEOUT_READ)
    {
        uint8_t purge_flags[4];

        if (!port_smoke_length_response(
                event,
                fixture,
                &length_response) ||
            length_response.io.io_status != PORT_SMOKE_IO_SUCCESS ||
            length_response.length != 0u)
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            length_response.io.io_status);
            return;
        }
        port_smoke_write_u32_le(
            purge_flags,
            PORT_SMOKE_PURGE_RX_ABORT |
                PORT_SMOKE_PURGE_TX_ABORT);
        status = port_smoke_send_control(
            fixture,
            peer,
            PORT_SMOKE_WAIT_PURGE_CANCEL,
            0u,
            RDP_PORT_REDIRECTION_IOCTL_SERIAL_PURGE,
            purge_flags,
            sizeof(purge_flags));
    }
    else if (stage == PORT_SMOKE_WAIT_PURGE_CANCEL)
    {
        static const uint8_t unplug_byte = 0x5au;

        if (!port_smoke_length_response(
                event,
                fixture,
                &length_response) ||
            length_response.io.io_status != PORT_SMOKE_IO_SUCCESS ||
            length_response.length != 0u)
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            length_response.io.io_status);
            return;
        }
        if ((fixture->slave_fd >= 0 &&
             close(fixture->slave_fd) != 0) ||
            fixture->master_fd < 0 ||
            close(fixture->master_fd) != 0)
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_IO_ERROR,
                            0u);
            return;
        }
        fixture->slave_fd = -1;
        fixture->master_fd = -1;
        status = port_smoke_send_write(
            fixture,
            peer,
            PORT_SMOKE_WAIT_UNPLUG_WRITE,
            &unplug_byte,
            1u);
    }
    else if (stage == PORT_SMOKE_WAIT_UNPLUG_WRITE)
    {
        if (!port_smoke_length_response(
                event,
                fixture,
                &length_response) ||
            length_response.io.io_status == PORT_SMOKE_IO_SUCCESS ||
            length_response.length != 0u)
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            length_response.io.io_status);
            return;
        }
        status = port_smoke_send_close(fixture,
                                       peer,
                                       PORT_SMOKE_WAIT_CLOSE);
    }
    else if (stage == PORT_SMOKE_WAIT_CLOSE)
    {
        rdp_device_redirection_io_completion response;

        if (rdp_filesystem_redirection_parse_close_response(
                event->payload,
                event->payload_len,
                &response) != LIBRDP_STATUS_OK ||
            response.device_id != fixture->device_id ||
            response.completion_id !=
                fixture->expected_completion_id ||
            response.io_status != PORT_SMOKE_IO_SUCCESS)
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            response.io_status);
            return;
        }
        atomic_store_explicit(&fixture->stage,
                              PORT_SMOKE_COMPLETE,
                              memory_order_release);
        return;
    }
    else
    {
        port_smoke_fail(fixture,
                        LIBRDP_STATUS_PROTOCOL_ERROR,
                        0u);
        return;
    }
    if (status != LIBRDP_STATUS_OK)
        port_smoke_fail(fixture, status, 0u);
}

/*
 * Drive the parallel-port lifecycle over RDPDR and verify output through an
 * independently held descriptor. The control checks distinguish a supported
 * status query from an unknown request that must be rejected explicitly.
 */
static void port_smoke_handle_parallel_completion(
    port_smoke_fixture* fixture,
    librdp_server_peer* peer,
    const librdp_server_extension_event* event)
{
    rdp_filesystem_redirection_length_response length_response;
    port_smoke_stage stage = PORT_SMOKE_FAILED;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!fixture || !peer || !event)
        return;
    stage = (port_smoke_stage)atomic_load_explicit(
        &fixture->stage,
        memory_order_acquire);
    atomic_fetch_add_explicit(&fixture->completions,
                              1u,
                              memory_order_relaxed);
    memset(&length_response, 0, sizeof(length_response));

    if (stage == PORT_SMOKE_WAIT_PARALLEL_CREATE)
    {
        rdp_filesystem_redirection_create_response response;

        memset(&response, 0, sizeof(response));
        if (rdp_filesystem_redirection_parse_create_response(
                event->payload,
                event->payload_len,
                &response) != LIBRDP_STATUS_OK ||
            response.io.device_id != fixture->device_id ||
            response.io.completion_id !=
                fixture->expected_completion_id ||
            response.io.io_status != PORT_SMOKE_IO_SUCCESS ||
            response.file_id == 0u)
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            response.io.io_status);
            return;
        }
        fixture->file_id = response.file_id;
        status = port_smoke_send_write(
            fixture,
            peer,
            PORT_SMOKE_WAIT_PARALLEL_WRITE,
            port_smoke_parallel_output,
            sizeof(port_smoke_parallel_output));
    }
    else if (stage == PORT_SMOKE_WAIT_PARALLEL_WRITE)
    {
        if (!port_smoke_length_response(
                event,
                fixture,
                &length_response) ||
            length_response.io.io_status != PORT_SMOKE_IO_SUCCESS ||
            length_response.length !=
                sizeof(port_smoke_parallel_output) ||
            !port_smoke_verify_parallel_output(fixture))
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            length_response.io.io_status);
            return;
        }
        status = port_smoke_send_control(
            fixture,
            peer,
            PORT_SMOKE_WAIT_PARALLEL_STATUS,
            4u,
            RDP_PORT_REDIRECTION_IOCTL_PAR_QUERY_INFORMATION,
            NULL,
            0u);
    }
    else if (stage == PORT_SMOKE_WAIT_PARALLEL_STATUS)
    {
        if (!port_smoke_length_response(
                event,
                fixture,
                &length_response) ||
            length_response.io.io_status != PORT_SMOKE_IO_SUCCESS ||
            length_response.length != 4u ||
            port_smoke_read_u32_le(length_response.buffer) != 0u)
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            length_response.io.io_status);
            return;
        }
        status = port_smoke_send_control(
            fixture,
            peer,
            PORT_SMOKE_WAIT_PARALLEL_UNSUPPORTED,
            4u,
            PORT_SMOKE_UNKNOWN_CONTROL,
            NULL,
            0u);
    }
    else if (stage == PORT_SMOKE_WAIT_PARALLEL_UNSUPPORTED)
    {
        if (!port_smoke_length_response(
                event,
                fixture,
                &length_response) ||
            length_response.io.io_status !=
                PORT_SMOKE_IO_NOT_SUPPORTED ||
            length_response.length != 0u)
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            length_response.io.io_status);
            return;
        }
        status = port_smoke_send_close(
            fixture,
            peer,
            PORT_SMOKE_WAIT_PARALLEL_CLOSE);
    }
    else if (stage == PORT_SMOKE_WAIT_PARALLEL_CLOSE)
    {
        rdp_device_redirection_io_completion response;

        memset(&response, 0, sizeof(response));
        if (rdp_filesystem_redirection_parse_close_response(
                event->payload,
                event->payload_len,
                &response) != LIBRDP_STATUS_OK ||
            response.device_id != fixture->device_id ||
            response.completion_id !=
                fixture->expected_completion_id ||
            response.io_status != PORT_SMOKE_IO_SUCCESS)
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            response.io_status);
            return;
        }
        atomic_store_explicit(&fixture->stage,
                              PORT_SMOKE_PARALLEL_COMPLETE,
                              memory_order_release);
        return;
    }
    else
    {
        port_smoke_fail(fixture,
                        LIBRDP_STATUS_PROTOCOL_ERROR,
                        0u);
        return;
    }
    if (status != LIBRDP_STATUS_OK)
        port_smoke_fail(fixture, status, 0u);
}

static void port_smoke_server_extension(
    librdp_server_peer* peer,
    const librdp_server_extension_event* event,
    void* user_data)
{
    port_smoke_fixture* fixture =
        (port_smoke_fixture*)user_data;
    port_smoke_stage stage = PORT_SMOKE_FAILED;

    if (!fixture || !peer || !event ||
        event->status != LIBRDP_STATUS_OK)
        return;
    stage = (port_smoke_stage)atomic_load_explicit(
        &fixture->stage,
        memory_order_acquire);
    if (event->message_type ==
            RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICELIST_ANNOUNCE &&
        (stage == PORT_SMOKE_WAIT_DEVICE ||
         stage == PORT_SMOKE_WAIT_PARALLEL_DEVICE))
    {
        rdp_device_redirection_device_list list;

        if (rdp_port_redirection_parse_device_list_announce(
                event->payload,
                event->payload_len,
                &list) != LIBRDP_STATUS_OK)
        {
            port_smoke_fail(fixture,
                            LIBRDP_STATUS_PROTOCOL_ERROR,
                            0u);
            return;
        }
        for (uint32_t index = 0u; index < list.count; index++)
        {
            if (list.devices[index].device_type ==
                fixture->device_type)
            {
                fixture->channel_id = event->channel_id;
                fixture->device_id =
                    list.devices[index].device_id;
                if (librdp_server_peer_send_device_reply(
                        peer,
                        fixture->channel_id,
                        fixture->extension_family,
                        fixture->device_id,
                        PORT_SMOKE_IO_SUCCESS) !=
                        LIBRDP_STATUS_OK ||
                    port_smoke_send_create(fixture, peer) !=
                        LIBRDP_STATUS_OK)
                {
                    port_smoke_fail(
                        fixture,
                        LIBRDP_STATUS_PROTOCOL_ERROR,
                        0u);
                }
                return;
            }
        }
        port_smoke_fail(fixture,
                        LIBRDP_STATUS_PROTOCOL_ERROR,
                        0u);
        return;
    }
    if (event->family == fixture->extension_family &&
        event->message_type ==
            RDP_DEVICE_REDIRECTION_PAKID_CORE_DEVICE_IOCOMPLETION)
    {
        if (fixture->extension_family ==
            LIBRDP_SERVER_EXTENSION_SERIAL_PORT)
            port_smoke_handle_completion(fixture, peer, event);
        else
            port_smoke_handle_parallel_completion(fixture,
                                                  peer,
                                                  event);
    }
}

static void* port_smoke_server_main(void* user_data)
{
    port_smoke_fixture* fixture =
        (port_smoke_fixture*)user_data;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    unsigned int attempt = 0u;

    if (!fixture)
        return NULL;
    fixture->status = LIBRDP_STATUS_NO_MEMORY;
    server = librdp_server_new(&fixture->config);
    if (!server)
        return NULL;
    fixture->status = librdp_server_enable_extension_provider(
        server,
        fixture->extension_family,
        1);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    fixture->status = librdp_server_listen(server);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    atomic_store_explicit(&fixture->port,
                          librdp_server_local_port(server),
                          memory_order_release);
    for (attempt = 0u;
         attempt < PORT_SMOKE_PUMP_LIMIT &&
         atomic_load_explicit(&fixture->stop,
                              memory_order_acquire) == 0u &&
         !peer;
         attempt++)
    {
        fixture->status =
            librdp_server_accept(server, 20, &peer);
        if (fixture->status != LIBRDP_STATUS_OK &&
            fixture->status != LIBRDP_STATUS_TIMEOUT)
            goto cleanup;
    }
    if (!peer)
    {
        fixture->status = LIBRDP_STATUS_TIMEOUT;
        goto cleanup;
    }
    fixture->status = librdp_server_peer_set_extension_callback(
        peer,
        port_smoke_server_extension,
        fixture);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    fixture->status = LIBRDP_STATUS_TIMEOUT;
    for (attempt = 0u;
         attempt < PORT_SMOKE_PUMP_LIMIT * 4u &&
         atomic_load_explicit(&fixture->stop,
                              memory_order_acquire) == 0u;
         attempt++)
    {
        librdp_status status =
            librdp_server_peer_run_once(peer, 20);
        port_smoke_stage stage =
            (port_smoke_stage)atomic_load_explicit(
                &fixture->stage,
                memory_order_acquire);

        if (status == LIBRDP_STATUS_CLOSED ||
            status == LIBRDP_STATUS_IO_ERROR)
        {
            fixture->status =
                port_smoke_stage_complete(stage)
                    ? LIBRDP_STATUS_OK
                    : status;
            break;
        }
        if (status != LIBRDP_STATUS_OK &&
            status != LIBRDP_STATUS_TIMEOUT)
        {
            fixture->status = status;
            break;
        }
        if (stage == PORT_SMOKE_FAILED)
        {
            fixture->status = fixture->failure_status;
            break;
        }
        if (port_smoke_stage_complete(stage))
            fixture->status = LIBRDP_STATUS_OK;
    }
    if (atomic_load_explicit(&fixture->stop,
                             memory_order_acquire) != 0u &&
        port_smoke_stage_complete(
            (port_smoke_stage)atomic_load_explicit(
                &fixture->stage,
                memory_order_acquire)))
        fixture->status = LIBRDP_STATUS_OK;

cleanup:
    if (peer)
    {
        (void)librdp_server_peer_close(peer);
        librdp_server_peer_free(peer);
    }
    if (server)
    {
        librdp_server_close(server);
        librdp_server_free(server);
    }
    return NULL;
}

static void port_smoke_client_event(librdp_session* session,
                                    const librdp_event* event,
                                    void* user_data)
{
    port_smoke_fixture* fixture =
        (port_smoke_fixture*)user_data;

    (void)session;
    if (!fixture || !event)
        return;
    if (event->type == LIBRDP_EVENT_STATE_CHANGED &&
        event->data.state.new_state == LIBRDP_SESSION_ACTIVE)
    {
        atomic_fetch_add_explicit(&fixture->active_events,
                                  1u,
                                  memory_order_relaxed);
    }
    else if (event->type == LIBRDP_EVENT_ERROR)
    {
        atomic_fetch_add_explicit(&fixture->client_errors,
                                  1u,
                                  memory_order_relaxed);
    }
}

static void port_smoke_trace(librdp_session* session,
                             const librdp_trace_record* record,
                             void* user_data)
{
    port_smoke_fixture* fixture =
        (port_smoke_fixture*)user_data;

    (void)session;
    if (!fixture || !record)
        return;
    if (getenv("LIBRDP_SMOKE_TRACE_OUTPUT") &&
        record->line)
        fprintf(stderr, "%s\n", record->line);
    if (record->level &&
        strcmp(record->level, "error") == 0)
    {
        atomic_fetch_add_explicit(&fixture->trace_errors,
                                  1u,
                                  memory_order_relaxed);
    }
}

static int port_smoke_run(
    librdp_server_extension_family extension_family)
{
    port_smoke_fixture fixture;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_trace_policy trace_policy;
    uint16_t port = 0u;
    unsigned int attempt = 0u;
    unsigned int expected_completions = 0u;
    port_smoke_stage initial_stage = PORT_SMOKE_FAILED;
    port_smoke_stage complete_stage = PORT_SMOKE_FAILED;
    int serial = 0;
    int thread_started = 0;
    int result = 1;

    serial =
        extension_family == LIBRDP_SERVER_EXTENSION_SERIAL_PORT;
    if (!serial &&
        extension_family != LIBRDP_SERVER_EXTENSION_PARALLEL_PORT)
        return 2;
    memset(&fixture, 0, sizeof(fixture));
    fixture.extension_family = extension_family;
    fixture.device_type =
        serial ? RDP_DEVICE_REDIRECTION_TYPE_SERIAL
               : RDP_DEVICE_REDIRECTION_TYPE_PARALLEL;
    fixture.master_fd = -1;
    fixture.slave_fd = -1;
    fixture.status = LIBRDP_STATUS_AGAIN;
    fixture.failure_status = LIBRDP_STATUS_OK;
    fixture.write_data_len =
        serial ? PORT_SMOKE_WRITE_BYTES : 0u;
    fixture.timeout_values[0] = UINT32_MAX;
    initial_stage =
        serial ? PORT_SMOKE_WAIT_DEVICE
               : PORT_SMOKE_WAIT_PARALLEL_DEVICE;
    complete_stage =
        serial ? PORT_SMOKE_COMPLETE
               : PORT_SMOKE_PARALLEL_COMPLETE;
    expected_completions = serial ? 14u : 5u;
    atomic_init(&fixture.port, 0u);
    atomic_init(&fixture.stop, 0u);
    atomic_init(&fixture.stage, (unsigned int)initial_stage);
    atomic_init(&fixture.completions, 0u);
    atomic_init(&fixture.active_events, 0u);
    atomic_init(&fixture.client_errors, 0u);
    atomic_init(&fixture.trace_errors, 0u);
    REQUIRE(serial ? port_smoke_prepare_pty(&fixture)
                   : port_smoke_prepare_parallel_file(&fixture));
    if (serial)
    {
        fixture.write_data =
            (uint8_t*)malloc(fixture.write_data_len);
        REQUIRE(fixture.write_data != NULL);
        for (size_t index = 0u;
             index < fixture.write_data_len;
             index++)
            fixture.write_data[index] = port_smoke_pattern(index);
    }

    REQUIRE(librdp_server_config_init(&fixture.config) ==
            LIBRDP_STATUS_OK);
    fixture.config.bind_address = "127.0.0.1";
    fixture.config.security_mode = LIBRDP_SECURITY_STANDARD;
    fixture.config.width = PORT_SMOKE_WIDTH;
    fixture.config.height = PORT_SMOKE_HEIGHT;
    REQUIRE(pthread_create(&fixture.thread,
                           NULL,
                           port_smoke_server_main,
                           &fixture) == 0);
    thread_started = 1;
    REQUIRE(port_smoke_wait_for_port(&fixture.port, &port));

    settings = librdp_settings_new();
    REQUIRE(settings != NULL);
    REQUIRE(librdp_settings_set_target(settings,
                                       "127.0.0.1") ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_port(settings, port) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_security_mode(
                settings,
                LIBRDP_SECURITY_STANDARD) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_desktop_size(
                settings,
                PORT_SMOKE_WIDTH,
                PORT_SMOKE_HEIGHT) == LIBRDP_STATUS_OK);
    if (serial)
    {
        REQUIRE(librdp_settings_add_serial_port(
                    settings,
                    "COM1:",
                    fixture.slave_path) ==
                LIBRDP_STATUS_OK);
    }
    else
    {
        REQUIRE(librdp_settings_add_parallel_port(
                    settings,
                    "LPT1:",
                    fixture.slave_path) ==
                LIBRDP_STATUS_OK);
    }
    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
    librdp_session_set_event_callback(session,
                                      port_smoke_client_event,
                                      &fixture);
    REQUIRE(librdp_trace_policy_init(&trace_policy) ==
            LIBRDP_STATUS_OK);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.hex_bytes = 96u;
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = port_smoke_trace;
    trace_policy.callback_user_data = &fixture;
    trace_policy.trace_id =
        serial ? "serial-port-smoke"
               : "parallel-port-smoke";
    REQUIRE(librdp_session_set_trace_policy(
                session,
                &trace_policy) == LIBRDP_STATUS_OK);
    REQUIRE(librdp_session_connect(session) ==
            LIBRDP_STATUS_OK);

    for (attempt = 0u;
         attempt < PORT_SMOKE_PUMP_LIMIT * 4u;
         attempt++)
    {
        librdp_status status =
            librdp_session_run_once(session, 20);
        port_smoke_stage stage =
            (port_smoke_stage)atomic_load_explicit(
                &fixture.stage,
                memory_order_acquire);

        REQUIRE(status == LIBRDP_STATUS_OK);
        if (port_smoke_stage_complete(stage) ||
            stage == PORT_SMOKE_FAILED)
            break;
    }
    REQUIRE(attempt < PORT_SMOKE_PUMP_LIMIT * 4u);
    REQUIRE(atomic_load_explicit(&fixture.stage,
                                 memory_order_acquire) ==
            (unsigned int)complete_stage);
    REQUIRE(fixture.failure_status == LIBRDP_STATUS_OK);
    REQUIRE(fixture.failure_io_status == 0u);
    if (serial)
    {
        REQUIRE(fixture.partial_written > 0u);
        REQUIRE(fixture.partial_written <
                fixture.write_data_len);
    }
    REQUIRE(atomic_load_explicit(&fixture.completions,
                                 memory_order_acquire) ==
            expected_completions);
    REQUIRE(atomic_load_explicit(&fixture.active_events,
                                 memory_order_acquire) == 1u);
    REQUIRE(atomic_load_explicit(&fixture.client_errors,
                                 memory_order_acquire) == 0u);
    REQUIRE(atomic_load_explicit(&fixture.trace_errors,
                                 memory_order_acquire) == 0u);
    REQUIRE(librdp_session_disconnect(session) ==
            LIBRDP_STATUS_OK);
    result = 0;

cleanup:
    atomic_store_explicit(&fixture.stop,
                          1u,
                          memory_order_release);
    if (session)
    {
        if (librdp_session_get_state(session) !=
                LIBRDP_SESSION_CLOSED &&
            librdp_session_get_state(session) !=
                LIBRDP_SESSION_CANCELLED)
            (void)librdp_session_disconnect(session);
        librdp_session_free(session);
    }
    librdp_settings_free(settings);
    if (thread_started)
    {
        if (pthread_join(fixture.thread, NULL) != 0)
            result = 1;
        if (fixture.status != LIBRDP_STATUS_OK)
        {
            fprintf(stderr,
                    "%s server status=%s stage=%u failure=%s io_status=%u completions=%u\n",
                    serial ? "serial" : "parallel",
                    librdp_status_name(fixture.status),
                    atomic_load_explicit(&fixture.stage,
                                         memory_order_acquire),
                    librdp_status_name(fixture.failure_status),
                    fixture.failure_io_status,
                    atomic_load_explicit(&fixture.completions,
                                         memory_order_acquire));
            result = 1;
        }
    }
    if (fixture.master_fd >= 0)
        close(fixture.master_fd);
    if (fixture.slave_fd >= 0)
        close(fixture.slave_fd);
    if (!serial && fixture.slave_path[0] != '\0')
        (void)unlink(fixture.slave_path);
    free(fixture.write_data);
    return result;
}

int main(int argc, char** argv)
{
    if (argc == 2 && strcmp(argv[1], "serial") == 0)
        return port_smoke_run(
            LIBRDP_SERVER_EXTENSION_SERIAL_PORT);
    if (argc == 2 && strcmp(argv[1], "parallel") == 0)
        return port_smoke_run(
            LIBRDP_SERVER_EXTENSION_PARALLEL_PORT);
    fprintf(stderr,
            "usage: test_server_client_port_smoke serial|parallel\n");
    return 2;
}
