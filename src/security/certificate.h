/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: server certificate parsing and public-key encryption helpers.
 * Invariants: certificate bytes are validated before exposing a public key and
 * secret material is cleansed before release.
 * Ownership: rdp_security_public_key owns owned_modulus_le after successful
 * X.509 parsing and must be cleared with rdp_security_public_key_clear().
 * Threading: helpers are stateless; callers serialize access to shared buffers.
 * Trust boundary: server certificates and RSA blobs are untrusted wire data.
 */

#ifndef RDP_SECURITY_CERTIFICATE_H
#define RDP_SECURITY_CERTIFICATE_H

#include <librdp/error.h>

#include "common/buffer.h"

#include <stddef.h>
#include <stdint.h>

#define RDP_SECURITY_CLIENT_RANDOM_LEN 32u

typedef struct rdp_security_public_key
{
    uint32_t exponent;
    const uint8_t* modulus_le;
    uint8_t* owned_modulus_le;
    size_t modulus_len;
    uint32_t bit_len;
} rdp_security_public_key;

librdp_status rdp_security_parse_server_certificate(const void* data,
                                                    size_t length,
                                                    rdp_security_public_key* public_key);
void rdp_security_public_key_clear(rdp_security_public_key* public_key);
librdp_status rdp_security_generate_client_random(uint8_t random[RDP_SECURITY_CLIENT_RANDOM_LEN]);
librdp_status rdp_security_encrypt_client_random(const rdp_security_public_key* public_key,
                                                 const uint8_t random[RDP_SECURITY_CLIENT_RANDOM_LEN],
                                                 rdp_buffer* encrypted);
librdp_status rdp_security_encrypt_public_secret(const rdp_security_public_key* public_key,
                                                 const uint8_t* secret,
                                                 size_t secret_len,
                                                 rdp_buffer* encrypted);

#endif
