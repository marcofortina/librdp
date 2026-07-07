#ifndef RDP_TRANSPORT_TCP_H
#define RDP_TRANSPORT_TCP_H

#include <stdint.h>

#include <librdp/error.h>

librdp_status rdp_tcp_connect(const char* host, uint16_t port, int timeout_ms, int* out_fd);

#endif
