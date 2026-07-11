/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef RDP_TRANSPORT_TCP_H
#define RDP_TRANSPORT_TCP_H

#include <stdint.h>

#include <librdp/error.h>

librdp_status rdp_tcp_connect(const char* host, uint16_t port, int timeout_ms, int* out_fd);

#endif
