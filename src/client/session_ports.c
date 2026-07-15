/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: serial and parallel port device redirection.
 * Invariants: port handles are backed by redirected file slots, termios state is
 * synchronized before replies, and unsupported control codes fail explicitly.
 * Ownership: open file descriptors and per-port counters remain session-owned
 * until close, disconnect, or redirected handle cleanup.
 * Threading: port IRPs run on the session owner thread and use nonblocking host
 * descriptors where available.
 * Trust boundary: server-supplied control buffers, wait masks, offsets, and
 * write lengths are checked before host I/O or termios changes.
 */

#include "client/session_internal.h"
#include "common/trace.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

static librdp_status rdp_session_append_zeroes(rdp_buffer* buffer, uint32_t count)
{
    static const uint8_t zeroes[64] = {0};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    while (count > 0)
    {
        uint32_t chunk = count > sizeof(zeroes) ? (uint32_t)sizeof(zeroes) : count;

        status = rdp_buffer_append(buffer, zeroes, chunk);
        if (status != LIBRDP_STATUS_OK)
            return status;
        count -= chunk;
    }
    return LIBRDP_STATUS_OK;
}

static speed_t rdp_session_serial_to_speed(uint32_t baud, int* ok)
{
    if (ok)
        *ok = 1;
    switch (baud)
    {
#ifdef B110
        case 110: return B110;
#endif
#ifdef B300
        case 300: return B300;
#endif
#ifdef B600
        case 600: return B600;
#endif
#ifdef B1200
        case 1200: return B1200;
#endif
#ifdef B2400
        case 2400: return B2400;
#endif
#ifdef B4800
        case 4800: return B4800;
#endif
#ifdef B9600
        case 9600: return B9600;
#endif
#ifdef B19200
        case 19200: return B19200;
#endif
#ifdef B38400
        case 38400: return B38400;
#endif
#ifdef B57600
        case 57600: return B57600;
#endif
#ifdef B115200
        case 115200: return B115200;
#endif
#ifdef B230400
        case 230400: return B230400;
#endif
        default:
            if (ok)
                *ok = 0;
            return B9600;
    }
}

static uint32_t rdp_session_speed_to_serial(speed_t speed)
{
    switch (speed)
    {
#ifdef B110
        case B110: return 110;
#endif
#ifdef B300
        case B300: return 300;
#endif
#ifdef B600
        case B600: return 600;
#endif
#ifdef B1200
        case B1200: return 1200;
#endif
#ifdef B2400
        case B2400: return 2400;
#endif
#ifdef B4800
        case B4800: return 4800;
#endif
#ifdef B9600
        case B9600: return 9600;
#endif
#ifdef B19200
        case B19200: return 19200;
#endif
#ifdef B38400
        case B38400: return 38400;
#endif
#ifdef B57600
        case B57600: return 57600;
#endif
#ifdef B115200
        case B115200: return 115200;
#endif
#ifdef B230400
        case B230400: return 230400;
#endif
        default: return 9600;
    }
}

static void rdp_session_port_init_defaults(rdp_session_redirected_file* port, uint8_t type)
{
    if (!port)
        return;
    port->port_type = type;
    port->serial_baud_rate = 9600;
    port->serial_line_control[0] = 0;
    port->serial_line_control[1] = 0;
    port->serial_line_control[2] = 8;
}

static uint32_t rdp_session_port_apply_baud(rdp_session_redirected_file* port, uint32_t baud)
{
    struct termios tio;
    int ok = 0;
    speed_t speed = 0;

    if (!port || port->fd < 0)
        return RDP_SESSION_DEVICE_NO_SUCH_FILE;
    port->serial_baud_rate = baud;
    if (!isatty(port->fd))
        return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    speed = rdp_session_serial_to_speed(baud, &ok);
    if (!ok || tcgetattr(port->fd, &tio) != 0)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (cfsetispeed(&tio, speed) != 0 || cfsetospeed(&tio, speed) != 0 ||
        tcsetattr(port->fd, TCSANOW, &tio) != 0)
        return rdp_session_errno_to_device_status(errno);
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static uint32_t rdp_session_port_refresh_baud(rdp_session_redirected_file* port)
{
    struct termios tio;

    if (!port || port->fd < 0 || !isatty(port->fd))
        return port ? port->serial_baud_rate : 0;
    if (tcgetattr(port->fd, &tio) == 0)
        port->serial_baud_rate = rdp_session_speed_to_serial(cfgetispeed(&tio));
    return port->serial_baud_rate;
}

static uint32_t rdp_session_port_apply_line_control(rdp_session_redirected_file* port,
                                                    const uint8_t* data,
                                                    uint32_t length)
{
    struct termios tio;
    tcflag_t bits = CS8;

    if (!port || port->fd < 0)
        return RDP_SESSION_DEVICE_NO_SUCH_FILE;
    if (!data || length < 3u)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    memcpy(port->serial_line_control, data, 3u);
    if (!isatty(port->fd))
        return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    if (tcgetattr(port->fd, &tio) != 0)
        return rdp_session_errno_to_device_status(errno);
    tio.c_cflag &= (tcflag_t)~(tcflag_t)(CSIZE | PARENB | PARODD | CSTOPB);
    switch (data[2])
    {
        case 5: bits = CS5; break;
        case 6: bits = CS6; break;
        case 7: bits = CS7; break;
        case 8: bits = CS8; break;
        default: return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    }
    tio.c_cflag |= bits | CLOCAL | CREAD;
    if (data[0] == 2)
        tio.c_cflag |= CSTOPB;
    if (data[1] != 0)
    {
        tio.c_cflag |= PARENB;
        if (data[1] == 1)
            tio.c_cflag |= PARODD;
    }
    if (tcsetattr(port->fd, TCSANOW, &tio) != 0)
        return rdp_session_errno_to_device_status(errno);
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

#if defined(TIOCM_DTR) || defined(TIOCM_RTS)
static uint32_t rdp_session_port_set_modem_flag(rdp_session_redirected_file* port, int bit, int enabled)
{
#ifdef TIOCMGET
    int flags = 0;

    if (!port || port->fd < 0)
        return RDP_SESSION_DEVICE_NO_SUCH_FILE;
    if (!isatty(port->fd))
        return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    if (ioctl(port->fd, TIOCMGET, &flags) != 0)
        return rdp_session_errno_to_device_status(errno);
    if (enabled)
        flags |= bit;
    else
        flags &= ~bit;
    if (ioctl(port->fd, TIOCMSET, &flags) != 0)
        return rdp_session_errno_to_device_status(errno);
#else
    (void)port;
    (void)bit;
    (void)enabled;
#endif
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}
#endif

static uint32_t rdp_session_port_modem_flags(rdp_session_redirected_file* port)
{
#ifdef TIOCMGET
    int flags = 0;

    if (!port || port->fd < 0 || !isatty(port->fd))
        return 0;
    if (ioctl(port->fd, TIOCMGET, &flags) != 0)
        return 0;
    return (uint32_t)flags;
#else
    (void)port;
    return 0;
#endif
}

static uint32_t rdp_session_port_set_modem_flags(rdp_session_redirected_file* port, uint32_t flags)
{
#ifdef TIOCMSET
    int native_flags = (int)flags;

    if (!port || port->fd < 0)
        return RDP_SESSION_DEVICE_NO_SUCH_FILE;
    if (!isatty(port->fd))
        return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    if (ioctl(port->fd, TIOCMSET, &native_flags) != 0)
        return rdp_session_errno_to_device_status(errno);
#else
    (void)port;
    (void)flags;
#endif
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

static uint32_t rdp_session_port_queue_depth(rdp_session_redirected_file* port, int output_queue)
{
    if (!port || port->fd < 0 || !isatty(port->fd))
        return 0;
    if (!output_queue)
    {
#ifdef FIONREAD
        int count = 0;

        if (ioctl(port->fd, FIONREAD, &count) == 0 && count > 0)
            return (uint32_t)count;
#endif
    }
    else
    {
#ifdef TIOCOUTQ
        int count = 0;

        if (ioctl(port->fd, TIOCOUTQ, &count) == 0 && count > 0)
            return (uint32_t)count;
#endif
    }
    return 0;
}

static uint32_t rdp_session_port_serial_wait_events(rdp_session_redirected_file* port)
{
    uint32_t events = RDP_PORT_REDIRECTION_SERIAL_EV_TXEMPTY;
#if defined(TIOCM_CTS) || defined(TIOCM_DSR) || defined(TIOCM_CAR) || defined(TIOCM_RNG)
    uint32_t modem_flags = 0;
#endif

    if (!port)
        return 0;
    if (rdp_session_port_queue_depth(port, 0) > 0)
        events |= RDP_PORT_REDIRECTION_SERIAL_EV_RXCHAR;
    if (rdp_session_port_queue_depth(port, 1) > 0)
        events &= ~RDP_PORT_REDIRECTION_SERIAL_EV_TXEMPTY;
#if defined(TIOCM_CTS) || defined(TIOCM_DSR) || defined(TIOCM_CAR) || defined(TIOCM_RNG)
    modem_flags = rdp_session_port_modem_flags(port);
#endif
#ifdef TIOCM_CTS
    if ((modem_flags & TIOCM_CTS) != 0)
        events |= RDP_PORT_REDIRECTION_SERIAL_EV_CTS;
#endif
#ifdef TIOCM_DSR
    if ((modem_flags & TIOCM_DSR) != 0)
        events |= RDP_PORT_REDIRECTION_SERIAL_EV_DSR;
#endif
#ifdef TIOCM_CAR
    if ((modem_flags & TIOCM_CAR) != 0)
        events |= RDP_PORT_REDIRECTION_SERIAL_EV_RLSD;
#endif
#ifdef TIOCM_RNG
    if ((modem_flags & TIOCM_RNG) != 0)
        events |= RDP_PORT_REDIRECTION_SERIAL_EV_RING;
#endif
    return events;
}

static librdp_status rdp_session_port_write_comm_status(rdp_session_redirected_file* port,
                                                        rdp_buffer* output)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!port || !output)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(output, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(output, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(output, rdp_session_port_queue_depth(port, 0));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(output, rdp_session_port_queue_depth(port, 1));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(output, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(output, 0);
    return status;
}

static librdp_status rdp_session_port_write_properties(rdp_session_redirected_file* port,
                                                       rdp_buffer* output)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t baud = rdp_session_port_refresh_baud(port);

    if (!port || !output)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(output, 64u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(output, 2u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(output, 0x00000001u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(output, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(output, 4096u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(output, 4096u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(output, 0x10000000u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(output, 1u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(output, 0x000000ffu);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(output, 0x0000007fu);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(output, 0x1fffffffU);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(output, 0x001eu);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(output, 0x1f1fu);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(output, baud);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(output, rdp_session_port_queue_depth(port, 0));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(output, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(output, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(output, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(output, 0);
    return status;
}

static librdp_status rdp_session_port_write_stats(rdp_session_redirected_file* port,
                                                  rdp_buffer* output)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!port || !output)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u32_le(output, (uint32_t)(port->serial_rx_count & 0xffffffffu));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(output, (uint32_t)(port->serial_tx_count & 0xffffffffu));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_append_zeroes(output, 40u);
    return status;
}

static uint32_t rdp_session_port_purge(rdp_session_redirected_file* port,
                                       const uint8_t* data,
                                       uint32_t length)
{
    uint32_t flags = 0;
    int queue = 0;

    if (!port || port->fd < 0)
        return RDP_SESSION_DEVICE_NO_SUCH_FILE;
    if (!data || length < 4u)
        return RDP_SESSION_DEVICE_INVALID_PARAMETER;
    flags = rdp_session_read_u32_le_unaligned(data);
    if (!isatty(port->fd))
        return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    if ((flags & 0x00000008u) != 0)
        queue = TCIFLUSH;
    if ((flags & 0x00000004u) != 0)
        queue = queue == TCIFLUSH ? TCIOFLUSH : TCOFLUSH;
    if (queue != 0 && tcflush(port->fd, queue) != 0)
        return rdp_session_errno_to_device_status(errno);
    return RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
}

/*
 * Handle serial-port control requests for redirected ports. Termios-style
 * configuration, modem status, timeout state, and unsupported controls are
 * normalized into protocol completions.
 */
static librdp_status rdp_session_port_control_serial(rdp_session_redirected_file* port,
                                                     const rdp_filesystem_redirection_control_request* request,
                                                     rdp_buffer* output,
                                                     uint32_t* io_status)
{
    uint32_t code = 0;

    if (!port || !request || !output || !io_status)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    code = request->io_control_code;
    *io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    switch (code)
    {
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_BAUD_RATE:
            if (request->input_buffer_length < 4u)
                *io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
            else
                *io_status = rdp_session_port_apply_baud(port,
                                                         rdp_session_read_u32_le_unaligned(request->input_buffer));
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_BAUD_RATE:
            return rdp_buffer_append_u32_le(output, rdp_session_port_refresh_baud(port));
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_LINE_CONTROL:
            *io_status = rdp_session_port_apply_line_control(port,
                                                             request->input_buffer,
                                                             request->input_buffer_length);
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_LINE_CONTROL:
            return rdp_buffer_append(output, port->serial_line_control, sizeof(port->serial_line_control));
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_TIMEOUTS:
            if (request->input_buffer_length < sizeof(port->serial_timeouts))
                *io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
            else
            {
                for (uint32_t i = 0; i < 5u; i++)
                    port->serial_timeouts[i] =
                        rdp_session_read_u32_le_unaligned(request->input_buffer + (i * 4u));
            }
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_TIMEOUTS:
            for (uint32_t i = 0; i < 5u; i++)
            {
                librdp_status status = rdp_buffer_append_u32_le(output, port->serial_timeouts[i]);
                if (status != LIBRDP_STATUS_OK)
                    return status;
            }
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_CHARS:
            if (request->input_buffer_length < sizeof(port->serial_chars))
                *io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
            else
                memcpy(port->serial_chars, request->input_buffer, sizeof(port->serial_chars));
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_CHARS:
            return rdp_buffer_append(output, port->serial_chars, sizeof(port->serial_chars));
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_HANDFLOW:
            if (request->input_buffer_length < sizeof(port->serial_handflow))
                *io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
            else
                memcpy(port->serial_handflow, request->input_buffer, sizeof(port->serial_handflow));
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_HANDFLOW:
            return rdp_buffer_append(output, port->serial_handflow, sizeof(port->serial_handflow));
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_WAIT_MASK:
            if (request->input_buffer_length < 4u)
                *io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
            else
                port->serial_wait_mask = rdp_session_read_u32_le_unaligned(request->input_buffer);
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_WAIT_MASK:
            return rdp_buffer_append_u32_le(output, port->serial_wait_mask);
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_WAIT_ON_MASK:
            return rdp_buffer_append_u32_le(
                output,
                rdp_port_redirection_serial_wait_result(port->serial_wait_mask,
                                                        rdp_session_port_serial_wait_events(port)));
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_DTR:
#ifdef TIOCM_DTR
            *io_status = rdp_session_port_set_modem_flag(port, TIOCM_DTR, 1);
#endif
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_CLR_DTR:
#ifdef TIOCM_DTR
            *io_status = rdp_session_port_set_modem_flag(port, TIOCM_DTR, 0);
#endif
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_RTS:
#ifdef TIOCM_RTS
            *io_status = rdp_session_port_set_modem_flag(port, TIOCM_RTS, 1);
#endif
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_CLR_RTS:
#ifdef TIOCM_RTS
            *io_status = rdp_session_port_set_modem_flag(port, TIOCM_RTS, 0);
#endif
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_MODEMSTATUS:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_DTRRTS:
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_MODEM_CONTROL:
            return rdp_buffer_append_u32_le(output, rdp_session_port_modem_flags(port));
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_IMMEDIATE_CHAR:
            if (request->input_buffer_length < 1u)
                *io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
            else if (write(port->fd, request->input_buffer, 1u) < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                *io_status = rdp_session_errno_to_device_status(errno);
            else
                port->serial_tx_count++;
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_BREAK_ON:
            if (isatty(port->fd) &&
#ifdef TIOCSBRK
                ioctl(port->fd, TIOCSBRK, 0) != 0
#else
                tcsendbreak(port->fd, 0) != 0
#endif
            )
                *io_status = rdp_session_errno_to_device_status(errno);
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_COMMSTATUS:
            return rdp_session_port_write_comm_status(port, output);
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_PROPERTIES:
            return rdp_session_port_write_properties(port, output);
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_CONFIG_SIZE:
            return rdp_buffer_append_u32_le(output, 0);
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_GET_STATS:
            return rdp_session_port_write_stats(port, output);
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_CLEAR_STATS:
            port->serial_rx_count = 0;
            port->serial_tx_count = 0;
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_PURGE:
            *io_status = rdp_session_port_purge(port,
                                                request->input_buffer,
                                                request->input_buffer_length);
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_QUEUE_SIZE:
            if (request->input_buffer_length < 8u)
                *io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_XOFF:
            if (isatty(port->fd) && tcflow(port->fd, TCOOFF) != 0)
                *io_status = rdp_session_errno_to_device_status(errno);
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_XON:
            if (isatty(port->fd) && tcflow(port->fd, TCOON) != 0)
                *io_status = rdp_session_errno_to_device_status(errno);
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_BREAK_OFF:
            if (isatty(port->fd))
            {
#ifdef TIOCCBRK
                if (ioctl(port->fd, TIOCCBRK, 0) != 0)
                    *io_status = rdp_session_errno_to_device_status(errno);
#endif
            }
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_RESET_DEVICE:
            if (isatty(port->fd) && tcflush(port->fd, TCIOFLUSH) != 0)
                *io_status = rdp_session_errno_to_device_status(errno);
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_XOFF_COUNTER:
            if (request->input_buffer_length < 8u)
                *io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_LSRMST_INSERT:
            if (request->input_buffer_length < 1u)
                *io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_MODEM_CONTROL:
            if (request->input_buffer_length < 4u)
                *io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
            else
                *io_status = rdp_session_port_set_modem_flags(port,
                                                              rdp_session_read_u32_le_unaligned(
                                                                  request->input_buffer));
            return LIBRDP_STATUS_OK;
        case RDP_PORT_REDIRECTION_IOCTL_SERIAL_SET_FIFO_CONTROL:
            if (request->input_buffer_length < 4u)
                *io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
            return LIBRDP_STATUS_OK;
        default:
            *io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
            return LIBRDP_STATUS_OK;
    }
}

static librdp_status rdp_session_port_control_parallel(rdp_session_redirected_file* port,
                                                       const rdp_filesystem_redirection_control_request* request,
                                                       rdp_buffer* output,
                                                       uint32_t* io_status)
{
    static const char device_id[] = "MFG:librdp;MDL:Redirected Parallel Port;CLS:PRINTER;";
    uint32_t code = 0;

    if (!port || !request || !output || !io_status)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    (void)port;
    code = request->io_control_code;
    *io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    switch (code)
    {
        case RDP_PORT_REDIRECTION_IOCTL_PAR_QUERY_DEVICE_ID_SIZE:
            return rdp_buffer_append_u32_le(output, (uint32_t)sizeof(device_id));
        case RDP_PORT_REDIRECTION_IOCTL_PAR_QUERY_DEVICE_ID:
        case RDP_PORT_REDIRECTION_IOCTL_PAR_QUERY_RAW_DEVICE_ID:
            return rdp_buffer_append(output, device_id, sizeof(device_id));
        case RDP_PORT_REDIRECTION_IOCTL_IEEE1284_GET_MODE:
        case RDP_PORT_REDIRECTION_IOCTL_PAR_GET_DEFAULT_MODES:
        case RDP_PORT_REDIRECTION_IOCTL_PAR_IS_PORT_FREE:
            return rdp_buffer_append_u32_le(output, 1u);
        case RDP_PORT_REDIRECTION_IOCTL_PAR_GET_DEVICE_CAPS:
            return rdp_buffer_append_u32_le(output, 0u);
        case RDP_PORT_REDIRECTION_IOCTL_PAR_QUERY_INFORMATION:
            return rdp_session_append_zeroes(output, 4u);
        case RDP_PORT_REDIRECTION_IOCTL_PAR_SET_INFORMATION:
        case RDP_PORT_REDIRECTION_IOCTL_IEEE1284_NEGOTIATE:
        case RDP_PORT_REDIRECTION_IOCTL_PAR_SET_WRITE_ADDRESS:
        case RDP_PORT_REDIRECTION_IOCTL_PAR_SET_READ_ADDRESS:
            return LIBRDP_STATUS_OK;
        default:
            *io_status = RDP_SESSION_DEVICE_NOT_SUPPORTED;
            return LIBRDP_STATUS_OK;
    }
}

static librdp_status rdp_session_send_port_create_response(librdp_session* session,
                                                           const rdp_device_redirection_io_request* request,
                                                           uint32_t io_status,
                                                           uint32_t file_id)
{
    rdp_buffer response;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_create_response(&response,
                                                              request->device_id,
                                                              request->completion_id,
                                                              io_status,
                                                              file_id,
                                                              RDP_FILESYSTEM_REDIRECTION_CREATE_FILE_OPENED);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.port.create.response");
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_session_handle_port_create(librdp_session* session,
                                                    const rdp_device_redirection_io_request* request,
                                                    uint8_t port_type,
                                                    uint32_t port_index)
{
    rdp_session_redirected_file* port = NULL;
    const char* path = NULL;
    uint32_t file_id = 0;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    int fd = -1;

    if (!session || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (port_type == RDP_SESSION_PORT_TYPE_SERIAL)
        path = librdp_settings_serial_port_path(session->settings, port_index);
    else
        path = librdp_settings_parallel_port_path(session->settings, port_index);
    if (!path)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_DEVICE;
    else
    {
        fd = open(path,
                  port_type == RDP_SESSION_PORT_TYPE_SERIAL ?
                      (O_RDWR | O_NOCTTY | O_NONBLOCK) :
                      (O_RDWR | O_NONBLOCK));
        if (fd < 0 && port_type == RDP_SESSION_PORT_TYPE_PARALLEL)
            fd = open(path, O_WRONLY | O_NONBLOCK);
        if (fd < 0)
            io_status = rdp_session_errno_to_device_status(errno);
        else
        {
            port = rdp_session_redirected_file_alloc(session, request->device_id, &file_id);
            if (!port)
                io_status = RDP_SESSION_DEVICE_TOO_MANY_OPENED_FILES;
            else
            {
                port->fd = fd;
                fd = -1;
                rdp_session_port_init_defaults(port, port_type);
            }
        }
    }
    if (fd >= 0)
        close(fd);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.rdpdr.port.create",
                    "device_id=%u completion_id=%u file_id=%u type=%u index=%u status=%u",
                    request->device_id,
                    request->completion_id,
                    file_id,
                    port_type,
                    port_index,
                    io_status);
    return rdp_session_send_port_create_response(session, request, io_status, file_id);
}

static librdp_status rdp_session_handle_port_close(librdp_session* session,
                                                   const rdp_device_redirection_io_request* request)
{
    rdp_session_redirected_file* port = NULL;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    port = rdp_session_redirected_file_find(session, request->device_id, request->file_id);
    if (!port)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
    else
    {
        if (port->fd >= 0 && close(port->fd) != 0)
            io_status = rdp_session_errno_to_device_status(errno);
        port->fd = -1;
        rdp_session_redirected_file_reset(port);
    }
    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_close_response(&response,
                                                             request->device_id,
                                                             request->completion_id,
                                                             io_status);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.port.close.response");
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_session_handle_port_read(librdp_session* session,
                                                  const uint8_t* data,
                                                  size_t data_len)
{
    rdp_filesystem_redirection_read_request request;
    rdp_session_redirected_file* port = NULL;
    rdp_buffer response;
    uint8_t* payload = NULL;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t payload_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_port_redirection_parse_read_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (request.length > RDP_SESSION_MAX_FILE_IO_BYTES)
        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
    else
    {
        port = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
        if (!port)
            io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
        else if (request.length > 0)
        {
            payload = (uint8_t*)malloc(request.length);
            if (!payload)
                return LIBRDP_STATUS_NO_MEMORY;
            for (;;)
            {
                ssize_t got = read(port->fd, payload, request.length);

                if (got < 0 && errno == EINTR)
                    continue;
                if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                    got = 0;
                if (got < 0)
                    io_status = rdp_session_errno_to_device_status(errno);
                else
                {
                    payload_len = (uint32_t)got;
                    port->serial_rx_count += (uint64_t)payload_len;
                }
                break;
            }
        }
    }
    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_read_response(&response,
                                                            request.io.device_id,
                                                            request.io.completion_id,
                                                            io_status,
                                                            io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ?
                                                                payload :
                                                                NULL,
                                                            io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ?
                                                                payload_len :
                                                                0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.port.read.response");
    rdp_buffer_free(&response);
    free(payload);
    return status;
}

static librdp_status rdp_session_handle_port_write(librdp_session* session,
                                                   const uint8_t* data,
                                                   size_t data_len)
{
    rdp_filesystem_redirection_write_request request;
    rdp_session_redirected_file* port = NULL;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    uint32_t written = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_port_redirection_parse_write_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (request.length > RDP_SESSION_MAX_FILE_IO_BYTES)
        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
    else
    {
        port = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
        if (!port)
            io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
        else
        {
            const uint8_t* cursor = request.data;
            uint32_t remaining = request.length;

            while (remaining > 0)
            {
                ssize_t count = write(port->fd, cursor, remaining);

                if (count < 0 && errno == EINTR)
                    continue;
                if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                    break;
                if (count <= 0)
                {
                    io_status = count < 0 ? rdp_session_errno_to_device_status(errno)
                                          : RDP_SESSION_DEVICE_UNSUCCESSFUL;
                    break;
                }
                cursor += (size_t)count;
                remaining -= (uint32_t)count;
                written += (uint32_t)count;
                port->serial_tx_count += (uint64_t)count;
            }
        }
    }
    rdp_buffer_init(&response);
    status = rdp_filesystem_redirection_write_write_response(&response,
                                                             request.io.device_id,
                                                             request.io.completion_id,
                                                             io_status,
                                                             written);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.port.write.response");
    rdp_buffer_free(&response);
    return status;
}

static librdp_status rdp_session_handle_port_control(librdp_session* session,
                                                     const uint8_t* data,
                                                     size_t data_len,
                                                     uint8_t port_type)
{
    rdp_filesystem_redirection_control_request request;
    rdp_session_redirected_file* port = NULL;
    rdp_buffer output;
    rdp_buffer response;
    uint32_t io_status = RDP_DEVICE_REDIRECTION_STATUS_SUCCESS;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_port_redirection_parse_control_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    port = rdp_session_redirected_file_find(session, request.io.device_id, request.io.file_id);
    rdp_buffer_init(&output);
    rdp_buffer_init(&response);
    if (!port)
        io_status = RDP_SESSION_DEVICE_NO_SUCH_FILE;
    else if (port_type == RDP_SESSION_PORT_TYPE_SERIAL && port->port_type == RDP_SESSION_PORT_TYPE_SERIAL)
        status = rdp_session_port_control_serial(port, &request, &output, &io_status);
    else if (port_type == RDP_SESSION_PORT_TYPE_PARALLEL && port->port_type == RDP_SESSION_PORT_TYPE_PARALLEL)
        status = rdp_session_port_control_parallel(port, &request, &output, &io_status);
    else
        io_status = RDP_SESSION_DEVICE_INVALID_PARAMETER;
    if (status == LIBRDP_STATUS_OK &&
        io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS &&
        output.length > request.output_buffer_length)
        io_status = RDP_SESSION_DEVICE_BUFFER_TOO_SMALL;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_port_redirection_write_control_response(&response,
                                                             request.io.device_id,
                                                             request.io.completion_id,
                                                             io_status,
                                                             io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ?
                                                                 output.data :
                                                                 NULL,
                                                             io_status == RDP_DEVICE_REDIRECTION_STATUS_SUCCESS ?
                                                                 (uint32_t)output.length :
                                                                 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_device_redirection_packet(session,
                                                            &response,
                                                            "client.rdpdr.port.control.response");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.rdpdr.port.control",
                        "device_id=%u file_id=%u completion_id=%u type=%u ioctl=%u status=%u output_len=%u requested_output=%u",
                        request.io.device_id,
                        request.io.file_id,
                        request.io.completion_id,
                        port_type,
                        request.io_control_code,
                        io_status,
                        (unsigned)output.length,
                        request.output_buffer_length);
    rdp_buffer_free(&response);
    rdp_buffer_free(&output);
    return status;
}

librdp_status rdp_session_handle_port_io_request(librdp_session* session,
                                                        const uint8_t* data,
                                                        size_t data_len,
                                                        uint8_t port_type,
                                                        uint32_t port_index)
{
    rdp_device_redirection_io_request request;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_device_redirection_parse_io_request(data, data_len, &request);
    if (status != LIBRDP_STATUS_OK)
        return status;
    switch (request.major_function)
    {
        case RDP_DEVICE_REDIRECTION_IRP_CREATE:
            return rdp_session_handle_port_create(session, &request, port_type, port_index);
        case RDP_DEVICE_REDIRECTION_IRP_CLOSE:
            return rdp_session_handle_port_close(session, &request);
        case RDP_DEVICE_REDIRECTION_IRP_READ:
            return rdp_session_handle_port_read(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_WRITE:
            return rdp_session_handle_port_write(session, data, data_len);
        case RDP_DEVICE_REDIRECTION_IRP_DEVICE_CONTROL:
            return rdp_session_handle_port_control(session, data, data_len, port_type);
        default:
        {
            rdp_buffer response;

            rdp_buffer_init(&response);
            status = rdp_device_redirection_write_io_completion(&response,
                                                                request.device_id,
                                                                request.completion_id,
                                                                RDP_SESSION_DEVICE_NOT_SUPPORTED,
                                                                NULL,
                                                                0);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_send_device_redirection_packet(session,
                                                                    &response,
                                                                    "client.rdpdr.port.not_supported.response");
            rdp_buffer_free(&response);
            return status;
        }
    }
}
