/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for WebAuthn CBOR and RPC parser/writer paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "channels/webauthn_channel.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Fuzz target: exercises WebAuthn CBOR and RPC parser/writer paths with one
 * arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_webauthn_request request;
    rdp_webauthn_response response;
    rdp_buffer buffer;
    uint8_t command_payload[1] = {RDP_WEBAUTHN_CMD_MAKE_CREDENTIAL};
    uint8_t guid[RDP_WEBAUTHN_GUID_LENGTH] = {0};
    uint32_t value = 0;
    size_t bounded = size > RDP_WEBAUTHN_MAX_MESSAGE ? RDP_WEBAUTHN_MAX_MESSAGE : size;

    (void)rdp_webauthn_parse_request(data, size, &request);
    (void)rdp_webauthn_parse_response(data, size, &response);
    (void)rdp_webauthn_parse_u32_response(&response, &value);

    rdp_buffer_init(&buffer);
    (void)rdp_webauthn_write_request(&buffer,
                                     RDP_WEBAUTHN_COMMAND_WEB_AUTHN,
                                     RDP_WEBAUTHN_FLAG_UV_PREFERRED,
                                     command_payload,
                                     sizeof(command_payload),
                                     "example.test",
                                     guid);
    buffer.length = 0;
    (void)rdp_webauthn_write_request(&buffer,
                                     RDP_WEBAUTHN_COMMAND_CANCEL,
                                     0,
                                     guid,
                                     sizeof(guid),
                                     NULL,
                                     NULL);
    buffer.length = 0;
    (void)rdp_webauthn_write_response(&buffer, 0, data, bounded);
    buffer.length = 0;
    (void)rdp_webauthn_write_u32_response(&buffer, 0, (uint32_t)size);
    rdp_buffer_free(&buffer);
    return 0;
}
