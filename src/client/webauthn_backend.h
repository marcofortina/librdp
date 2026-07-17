/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: internal WebAuthn provider boundary for host authenticators.
 * Invariants: provider paths and CTAPHID payload lengths are validated before
 * native device access, and unavailable providers return UNSUPPORTED.
 * Ownership: caller owns request and response buffers; device metadata points
 * into the backend device object until that object leaves scope.
 * Threading: functions are synchronous to the session thread and bounded by
 * protocol timeouts; asynchronous providers preserve response ownership.
 * Trust boundary: host authenticator paths are local policy inputs, while CTAP
 * payload bytes are sensitive and must not be traced.
 */

#ifndef RDP_CLIENT_WEBAUTHN_BACKEND_H
#define RDP_CLIENT_WEBAUTHN_BACKEND_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "channels/webauthn_channel.h"
#include "common/buffer.h"

#ifndef PATH_MAX
#define RDP_WEBAUTHN_BACKEND_PATH_MAX 4096
#else
#define RDP_WEBAUTHN_BACKEND_PATH_MAX PATH_MAX
#endif

typedef struct rdp_webauthn_backend_fido2_device
{
    char path[RDP_WEBAUTHN_BACKEND_PATH_MAX];
    char manufacturer[128];
    char product[128];
    uint8_t aaguid[RDP_WEBAUTHN_GUID_LENGTH];
    rdp_webauthn_device_info info;
} rdp_webauthn_backend_fido2_device;

void rdp_webauthn_backend_fido2_info_init(rdp_webauthn_backend_fido2_device* device);
librdp_status rdp_webauthn_backend_select_fido2_device(
    const char* requested_path,
    rdp_webauthn_backend_fido2_device* device);
librdp_status rdp_webauthn_backend_fido2_exchange(
    const char* requested_path,
    const rdp_webauthn_request* request,
    rdp_webauthn_backend_fido2_device* device,
    rdp_buffer* ctap_response);

#endif
