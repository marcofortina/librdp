/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: CredSSP and NTLM message construction, wrapping, and TSRequest
 * exchange.
 * Invariants: cryptographic state changes occur only after complete input
 * validation and successful provider calls.
 * Ownership: credential-derived material remains transient and every
 * ASN.1/security buffer length is validated.
 * Threading: not thread-safe by itself; callers serialize access through the
 * owning session, stream, or backend object.
 * Trust boundary: remote certificate, token, and security-buffer bytes are
 * untrusted and secrets must not be logged.
 */


#include "nla/credssp.h"

#include "common/charset.h"
#include "common/stream.h"

#include <openssl/asn1.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define RDP_NTLM_NEGOTIATE_UNICODE 0x00000001u
#define RDP_NTLM_REQUEST_TARGET 0x00000004u
#define RDP_NTLM_NEGOTIATE_SIGN 0x00000010u
#define RDP_NTLM_NEGOTIATE_SEAL 0x00000020u
#define RDP_NTLM_NEGOTIATE_NTLM 0x00000200u
#define RDP_NTLM_NEGOTIATE_ALWAYS_SIGN 0x00008000u
#define RDP_NTLM_NEGOTIATE_EXTENDED_SESSION 0x00080000u
#define RDP_NTLM_NEGOTIATE_TARGET_INFO 0x00800000u
#define RDP_NTLM_NEGOTIATE_VERSION 0x02000000u
#define RDP_NTLM_NEGOTIATE_128 0x20000000u
#define RDP_NTLM_NEGOTIATE_KEY_EXCH 0x40000000u
#define RDP_NTLM_NEGOTIATE_56 0x80000000u

static uint16_t rdp_read_u16_le_bytes(const uint8_t* data)
{
    return (uint16_t)(data[0] | ((uint16_t)data[1] << 8));
}

static uint32_t rdp_read_u32_le_bytes(const uint8_t* data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static void rdp_write_u32_le_bytes(uint8_t* data, uint32_t value)
{
    data[0] = (uint8_t)(value & 0xffu);
    data[1] = (uint8_t)((value >> 8) & 0xffu);
    data[2] = (uint8_t)((value >> 16) & 0xffu);
    data[3] = (uint8_t)((value >> 24) & 0xffu);
}

librdp_status rdp_credssp_begin(bool enabled, rdp_credssp_state* state)
{
    if (!state)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!enabled)
    {
        *state = RDP_CREDSSP_DISABLED;
        return LIBRDP_STATUS_OK;
    }
    *state = RDP_CREDSSP_NEGOTIATING;
    return LIBRDP_STATUS_OK;
}

static int rdp_asn1_tag_class(uint8_t tag)
{
    return tag & 0xc0u;
}

static int rdp_asn1_tag_constructed(uint8_t tag)
{
    return (tag & 0x20u) != 0;
}

static int rdp_asn1_tag_number(uint8_t tag)
{
    return tag & 0x1fu;
}

static librdp_status rdp_der_wrap(rdp_buffer* output, uint8_t tag, const rdp_buffer* body)
{
    uint8_t header[16];
    unsigned char* p = header;
    size_t header_len = 0;
    int xclass = V_ASN1_UNIVERSAL;

    if (!output || !body)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_asn1_tag_number(tag) == 0x1f || body->length > INT_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_asn1_tag_class(tag) == 0x40)
        xclass = V_ASN1_APPLICATION;
    else if (rdp_asn1_tag_class(tag) == 0x80)
        xclass = V_ASN1_CONTEXT_SPECIFIC;
    else if (rdp_asn1_tag_class(tag) == 0xc0)
        xclass = V_ASN1_PRIVATE;
    ASN1_put_object(&p,
                    rdp_asn1_tag_constructed(tag),
                    (int)body->length,
                    rdp_asn1_tag_number(tag),
                    xclass);
    header_len = (size_t)(p - header);
    if (header_len == 0 || header_len > sizeof(header))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_buffer_append(output, header, header_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_NO_MEMORY;
    return rdp_buffer_append(output, body->data, body->length);
}

static librdp_status rdp_der_write_integer(rdp_buffer* output, uint32_t value)
{
    ASN1_INTEGER* integer = NULL;
    unsigned char* encoded = NULL;
    int encoded_len = 0;
    librdp_status status = LIBRDP_STATUS_PROTOCOL_ERROR;

    if (!output)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    integer = ASN1_INTEGER_new();
    if (!integer)
        return LIBRDP_STATUS_NO_MEMORY;
    if (ASN1_INTEGER_set_uint64(integer, value) == 1)
    {
        encoded_len = i2d_ASN1_INTEGER(integer, &encoded);
        if (encoded_len > 0)
            status = rdp_buffer_append(output, encoded, (size_t)encoded_len);
    }
    OPENSSL_free(encoded);
    ASN1_INTEGER_free(integer);
    return status;
}

static librdp_status rdp_der_write_octet_string(rdp_buffer* output, const uint8_t* data, size_t length)
{
    rdp_buffer body;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!output || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&body);
    status = rdp_buffer_append(&body, data, length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_wrap(output, 0x04, &body);
    rdp_buffer_free(&body);
    return status;
}

static librdp_status rdp_der_write_context(rdp_buffer* output, uint8_t index, const rdp_buffer* body)
{
    if (index > 30u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_der_wrap(output, (uint8_t)(0xa0u + index), body);
}

static librdp_status rdp_der_write_oid(rdp_buffer* output, const uint8_t* encoded, size_t length)
{
    rdp_buffer body;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!output || !encoded || length == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&body);
    status = rdp_buffer_append(&body, encoded, length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_wrap(output, 0x06, &body);
    rdp_buffer_free(&body);
    return status;
}

static size_t rdp_ascii_token_len(const char* text)
{
    return text ? strlen(text) : 0;
}

static librdp_status rdp_append_upper_ascii(rdp_buffer* buffer, const char* text, size_t length)
{
    size_t i = 0;

    if (!buffer || (!text && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < length; i++)
    {
        int ch = (unsigned char)text[i];
        librdp_status status = rdp_buffer_append_u8(buffer, (uint8_t)toupper(ch));
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_ntlm_write_security_buffer(rdp_buffer* buffer, size_t length, size_t offset)
{
    if (!buffer || length > 0xffffu || offset > 0xffffffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append_u16_le(buffer, (uint16_t)length) == LIBRDP_STATUS_OK &&
                   rdp_buffer_append_u16_le(buffer, (uint16_t)length) == LIBRDP_STATUS_OK &&
                   rdp_buffer_append_u32_le(buffer, (uint32_t)offset) == LIBRDP_STATUS_OK
               ? LIBRDP_STATUS_OK
               : LIBRDP_STATUS_NO_MEMORY;
}

static librdp_status rdp_buffer_append_u64_le(rdp_buffer* buffer, uint64_t value)
{
    uint8_t bytes[8];
    size_t i = 0;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < sizeof(bytes); i++)
        bytes[i] = (uint8_t)((value >> (i * 8u)) & 0xffu);
    return rdp_buffer_append(buffer, bytes, sizeof(bytes));
}

static librdp_status rdp_append_utf16le_ascii(rdp_buffer* buffer, const char* text, int uppercase)
{
    const char* input = text ? text : "";
    char* normalized = NULL;
    librdp_status status = LIBRDP_STATUS_OK;
    size_t length = strlen(input);

    if (!buffer || length > 0x7fffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (uppercase)
    {
        normalized = (char*)malloc(length + 1u);
        if (!normalized)
            return LIBRDP_STATUS_NO_MEMORY;
        for (size_t i = 0; i < length; i++)
        {
            unsigned char ch = (unsigned char)input[i];

            normalized[i] = (ch >= 'a' && ch <= 'z') ? (char)(ch - ('a' - 'A')) : (char)ch;
        }
        normalized[length] = '\0';
        input = normalized;
    }
    status = rdp_charset_utf8_to_utf16le_buffer(input, 0, buffer);
    free(normalized);
    return status;
}

static int rdp_ascii_equal_fold(const char* left, const char* right)
{
    if (!left || !right)
        return left == right;
    while (*left && *right)
    {
        if (toupper((unsigned char)*left) != toupper((unsigned char)*right))
            return 0;
        left++;
        right++;
    }
    return *left == '\0' && *right == '\0';
}

static librdp_status rdp_utf16le_ascii_to_cstring(const uint8_t* data, size_t length, rdp_buffer* output)
{
    char* text = NULL;
    size_t text_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if ((!data && length > 0) || !output || (length % 2u) != 0 || (length / 2u) > 0x7fffu)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_charset_utf16le_to_utf8_alloc(data, length, 0, &text, &text_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(output, (const uint8_t*)text, text_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(output, 0);
    free(text);
    return status;
}

static CRYPTO_ONCE rdp_credssp_provider_once = CRYPTO_ONCE_STATIC_INIT;
static OSSL_PROVIDER* rdp_credssp_default_provider;
static OSSL_PROVIDER* rdp_credssp_legacy_provider;
static int rdp_credssp_legacy_ready;

static void rdp_credssp_provider_init(void)
{
    rdp_credssp_default_provider = OSSL_PROVIDER_load(NULL, "default");
    rdp_credssp_legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
    rdp_credssp_legacy_ready = rdp_credssp_legacy_provider != NULL;
}

static librdp_status rdp_credssp_legacy_provider_ensure(void)
{
    if (CRYPTO_THREAD_run_once(&rdp_credssp_provider_once, rdp_credssp_provider_init) != 1)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_credssp_legacy_ready ? LIBRDP_STATUS_OK : LIBRDP_STATUS_UNSUPPORTED;
}

static librdp_status rdp_md4_digest(const uint8_t* data, size_t length, uint8_t digest[16])
{
    EVP_MD* md = NULL;
    EVP_MD_CTX* context = NULL;
    unsigned int got = 0;
    librdp_status status = LIBRDP_STATUS_PROTOCOL_ERROR;

    if ((!data && length > 0) || !digest)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_credssp_legacy_provider_ensure();
    if (status != LIBRDP_STATUS_OK)
        return status;

    md = EVP_MD_fetch(NULL, "MD4", "provider=legacy");
    if (!md)
        return LIBRDP_STATUS_UNSUPPORTED;
    context = EVP_MD_CTX_new();
    if (!context)
    {
        EVP_MD_free(md);
        return LIBRDP_STATUS_NO_MEMORY;
    }

    if (EVP_DigestInit_ex(context, md, NULL) != 1)
        goto out;
    if (length > 0 && EVP_DigestUpdate(context, data, length) != 1)
        goto out;
    if (EVP_DigestFinal_ex(context, digest, &got) != 1 || got != 16u)
        goto out;
    status = LIBRDP_STATUS_OK;

out:
    EVP_MD_CTX_free(context);
    EVP_MD_free(md);
    return status;
}

static librdp_status rdp_hmac_md5_parts(const uint8_t* key,
                                        size_t key_len,
                                        const uint8_t* a,
                                        size_t a_len,
                                        const uint8_t* b,
                                        size_t b_len,
                                        const uint8_t* c,
                                        size_t c_len,
                                        uint8_t output[16])
{
    EVP_MAC* mac = NULL;
    EVP_MAC_CTX* context = NULL;
    OSSL_PARAM params[2];
    size_t out_len = 0;
    librdp_status status = LIBRDP_STATUS_PROTOCOL_ERROR;

    if (!key || (!a && a_len > 0) || (!b && b_len > 0) || (!c && c_len > 0) || !output)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    context = EVP_MAC_CTX_new(mac);
    if (!context)
    {
        EVP_MAC_free(mac);
        return LIBRDP_STATUS_NO_MEMORY;
    }
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "MD5", 0);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_MAC_init(context, key, key_len, params) != 1)
        goto out;
    if (a_len > 0 && EVP_MAC_update(context, a, a_len) != 1)
        goto out;
    if (b_len > 0 && EVP_MAC_update(context, b, b_len) != 1)
        goto out;
    if (c_len > 0 && EVP_MAC_update(context, c, c_len) != 1)
        goto out;
    if (EVP_MAC_final(context, output, &out_len, 16u) != 1 || out_len != 16u)
        goto out;
    status = LIBRDP_STATUS_OK;

out:
    EVP_MAC_CTX_free(context);
    EVP_MAC_free(mac);
    return status;
}

static librdp_status rdp_digest_parts(const EVP_MD* md,
                                      const uint8_t* a,
                                      size_t a_len,
                                      const uint8_t* b,
                                      size_t b_len,
                                      const uint8_t* c,
                                      size_t c_len,
                                      uint8_t* output,
                                      size_t output_len)
{
    EVP_MD_CTX* context = NULL;
    unsigned int got = 0;
    librdp_status status = LIBRDP_STATUS_PROTOCOL_ERROR;

    if (!md || (!a && a_len > 0) || (!b && b_len > 0) || (!c && c_len > 0) || !output || output_len > UINT_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    context = EVP_MD_CTX_new();
    if (!context)
        return LIBRDP_STATUS_NO_MEMORY;
    if (EVP_DigestInit_ex(context, md, NULL) != 1)
        goto out;
    if (a_len > 0 && EVP_DigestUpdate(context, a, a_len) != 1)
        goto out;
    if (b_len > 0 && EVP_DigestUpdate(context, b, b_len) != 1)
        goto out;
    if (c_len > 0 && EVP_DigestUpdate(context, c, c_len) != 1)
        goto out;
    if (EVP_DigestFinal_ex(context, output, &got) != 1 || got != output_len)
        goto out;
    status = LIBRDP_STATUS_OK;

out:
    EVP_MD_CTX_free(context);
    return status;
}

static librdp_status rdp_ntlm_rc4_init(rdp_ntlm_rc4_context* context, const uint8_t* key, size_t key_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !key || key_len == 0 || key_len > sizeof(context->key))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_credssp_legacy_provider_ensure();
    if (status != LIBRDP_STATUS_OK)
        return status;

    memset(context, 0, sizeof(*context));
    memcpy(context->key, key, key_len);
    context->key_len = key_len;
    context->initialized = 1;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_ntlm_rc4_discard(EVP_CIPHER_CTX* cipher_context, size_t length)
{
    uint8_t zero[256];
    uint8_t discard[256];
    librdp_status status = LIBRDP_STATUS_OK;

    memset(zero, 0, sizeof(zero));
    while (length > 0)
    {
        int out_len = 0;
        int chunk = length > sizeof(zero) ? (int)sizeof(zero) : (int)length;

        if (EVP_EncryptUpdate(cipher_context, discard, &out_len, zero, chunk) != 1 || out_len != chunk)
        {
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
            break;
        }
        length -= (size_t)chunk;
    }
    OPENSSL_cleanse(discard, sizeof(discard));
    return status;
}

static librdp_status rdp_ntlm_rc4_crypt(rdp_ntlm_rc4_context* context, uint8_t* data, size_t length)
{
    EVP_CIPHER* cipher = NULL;
    EVP_CIPHER_CTX* cipher_context = NULL;
    size_t offset = 0;
    librdp_status status = LIBRDP_STATUS_PROTOCOL_ERROR;

    if (!context || (!data && length > 0) || !context->initialized || context->key_len == 0 ||
        context->key_len > INT_MAX || SIZE_MAX - context->offset < length)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length == 0)
        return LIBRDP_STATUS_OK;

    status = rdp_credssp_legacy_provider_ensure();
    if (status != LIBRDP_STATUS_OK)
        return status;

    cipher = EVP_CIPHER_fetch(NULL, "RC4", "provider=legacy");
    if (!cipher)
        return LIBRDP_STATUS_UNSUPPORTED;
    cipher_context = EVP_CIPHER_CTX_new();
    if (!cipher_context)
    {
        EVP_CIPHER_free(cipher);
        return LIBRDP_STATUS_NO_MEMORY;
    }

    if (EVP_EncryptInit_ex(cipher_context, cipher, NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_set_key_length(cipher_context, (int)context->key_len) != 1 ||
        EVP_EncryptInit_ex(cipher_context, NULL, NULL, context->key, NULL) != 1)
        goto out;

    status = rdp_ntlm_rc4_discard(cipher_context, context->offset);
    if (status != LIBRDP_STATUS_OK)
        goto out;

    while (offset < length)
    {
        int out_len = 0;
        int chunk = length - offset > (size_t)INT_MAX ? INT_MAX : (int)(length - offset);

        if (EVP_EncryptUpdate(cipher_context, data + offset, &out_len, data + offset, chunk) != 1 ||
            out_len != chunk)
        {
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
            goto out;
        }
        offset += (size_t)chunk;
    }
    context->offset += length;
    status = LIBRDP_STATUS_OK;

out:
    EVP_CIPHER_CTX_free(cipher_context);
    EVP_CIPHER_free(cipher);
    return status;
}

static librdp_status rdp_ntlm_random_bytes(uint8_t* output, size_t length)
{
    if ((!output && length > 0) || length > INT_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length == 0)
        return LIBRDP_STATUS_OK;
    return RAND_bytes(output, (int)length) == 1 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

static uint64_t rdp_ntlm_filetime_now(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return 0;
    return ((uint64_t)ts.tv_sec + 11644473600ull) * 10000000ull + ((uint64_t)ts.tv_nsec / 100ull);
}

static int rdp_ntlm_target_info_has_eol(const uint8_t* data, size_t length)
{
    size_t offset = 0;

    if (!data && length > 0)
        return 0;
    while (offset + 4u <= length)
    {
        uint16_t av_id = rdp_read_u16_le_bytes(data + offset);
        uint16_t av_len = rdp_read_u16_le_bytes(data + offset + 2u);
        offset += 4u;
        if (av_id == 0 && av_len == 0)
            return 1;
        if ((size_t)av_len > length - offset)
            return 0;
        offset += av_len;
    }
    return 0;
}

static uint32_t rdp_ntlm_authenticate_flags(const rdp_ntlm_challenge* challenge)
{
    const uint32_t supported = RDP_NTLM_NEGOTIATE_UNICODE | RDP_NTLM_REQUEST_TARGET | RDP_NTLM_NEGOTIATE_SIGN |
                               RDP_NTLM_NEGOTIATE_SEAL | RDP_NTLM_NEGOTIATE_NTLM |
                               RDP_NTLM_NEGOTIATE_ALWAYS_SIGN | RDP_NTLM_NEGOTIATE_EXTENDED_SESSION |
                               RDP_NTLM_NEGOTIATE_TARGET_INFO | RDP_NTLM_NEGOTIATE_VERSION |
                               RDP_NTLM_NEGOTIATE_128 | RDP_NTLM_NEGOTIATE_KEY_EXCH | RDP_NTLM_NEGOTIATE_56;

    if (!challenge)
        return 0;
    return challenge->flags & supported;
}

uint32_t rdp_credssp_default_ntlm_challenge_flags(void)
{
    return RDP_NTLM_NEGOTIATE_UNICODE | RDP_NTLM_REQUEST_TARGET | RDP_NTLM_NEGOTIATE_SIGN |
           RDP_NTLM_NEGOTIATE_SEAL | RDP_NTLM_NEGOTIATE_NTLM |
           RDP_NTLM_NEGOTIATE_ALWAYS_SIGN | RDP_NTLM_NEGOTIATE_EXTENDED_SESSION |
           RDP_NTLM_NEGOTIATE_TARGET_INFO | RDP_NTLM_NEGOTIATE_VERSION |
           RDP_NTLM_NEGOTIATE_128 | RDP_NTLM_NEGOTIATE_KEY_EXCH | RDP_NTLM_NEGOTIATE_56;
}

static librdp_status rdp_ntlm_append_auth_domain(rdp_buffer* buffer,
                                                 const rdp_ntlm_challenge* challenge,
                                                 const char* domain)
{
    if (!buffer || !challenge)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (domain && domain[0] != '\0')
        return rdp_append_utf16le_ascii(buffer, domain, 0);
    if (challenge->target_name_len > 0)
        return rdp_buffer_append(buffer, challenge->target_name, challenge->target_name_len);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_ntlm_v2_hash(const char* username,
                                      const char* password,
                                      const uint8_t* target,
                                      size_t target_len,
                                      uint8_t hash[16])
{
    rdp_buffer password_utf16;
    rdp_buffer identity;
    uint8_t nt_hash[16];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!username || !password || (!target && target_len > 0) || !hash)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&password_utf16);
    rdp_buffer_init(&identity);

    status = rdp_append_utf16le_ascii(&password_utf16, password, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_md4_digest(password_utf16.data, password_utf16.length, nt_hash);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_append_utf16le_ascii(&identity, username, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&identity, target, target_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_hmac_md5_parts(nt_hash, sizeof(nt_hash), identity.data, identity.length, NULL, 0, NULL, 0, hash);

    if (password_utf16.data)
        OPENSSL_cleanse(password_utf16.data, password_utf16.length);
    if (identity.data)
        OPENSSL_cleanse(identity.data, identity.length);
    OPENSSL_cleanse(nt_hash, sizeof(nt_hash));
    rdp_buffer_free(&identity);
    rdp_buffer_free(&password_utf16);
    return status;
}

librdp_status rdp_credssp_write_ntlm_negotiate(rdp_buffer* buffer, const char* workstation, const char* domain)
{
    static const uint8_t signature[] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
    const size_t domain_len = rdp_ascii_token_len(domain);
    const size_t workstation_len = rdp_ascii_token_len(workstation);
    const size_t payload_offset = 40u;
    const uint32_t flags = RDP_NTLM_NEGOTIATE_UNICODE | RDP_NTLM_REQUEST_TARGET | RDP_NTLM_NEGOTIATE_SIGN |
                           RDP_NTLM_NEGOTIATE_SEAL | RDP_NTLM_NEGOTIATE_NTLM |
                           RDP_NTLM_NEGOTIATE_ALWAYS_SIGN | RDP_NTLM_NEGOTIATE_EXTENDED_SESSION |
                           RDP_NTLM_NEGOTIATE_TARGET_INFO | RDP_NTLM_NEGOTIATE_VERSION |
                           RDP_NTLM_NEGOTIATE_128 | RDP_NTLM_NEGOTIATE_KEY_EXCH | RDP_NTLM_NEGOTIATE_56;
    static const uint8_t version[] = {10, 0, 0, 0, 0, 0, 0, 15};
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || domain_len > 0xffffu || workstation_len > 0xffffu ||
        domain_len + workstation_len > 0xffffffffu - payload_offset)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append(buffer, signature, sizeof(signature));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_ntlm_write_security_buffer(buffer, domain_len, payload_offset);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_ntlm_write_security_buffer(buffer, workstation_len, payload_offset + domain_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, version, sizeof(version));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_append_upper_ascii(buffer, domain, domain_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_append_upper_ascii(buffer, workstation, workstation_len);
    return status;
}

librdp_status rdp_credssp_write_ntlm_challenge(rdp_buffer* buffer, const rdp_ntlm_challenge* challenge)
{
    static const uint8_t signature[] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
    const size_t payload_offset = 48u;
    size_t target_info_offset = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !challenge || !challenge->target_name || challenge->target_name_len == 0 ||
        !challenge->target_info || challenge->target_info_len == 0 ||
        challenge->target_name_len > UINT16_MAX || challenge->target_info_len > UINT16_MAX ||
        challenge->target_name_len > UINT32_MAX - payload_offset ||
        challenge->target_info_len > UINT32_MAX - payload_offset - challenge->target_name_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    target_info_offset = payload_offset + challenge->target_name_len;
    status = rdp_buffer_append(buffer, signature, sizeof(signature));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 2);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_ntlm_write_security_buffer(buffer, challenge->target_name_len, payload_offset);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, challenge->flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, challenge->server_challenge, sizeof(challenge->server_challenge));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u64_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_ntlm_write_security_buffer(buffer, challenge->target_info_len, target_info_offset);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, challenge->target_name, challenge->target_name_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, challenge->target_info, challenge->target_info_len);
    return status;
}

librdp_status rdp_credssp_write_spnego_ntlm_negotiate(rdp_buffer* buffer,
                                                      const uint8_t* ntlm_token,
                                                      size_t ntlm_token_len)
{
    static const uint8_t spnego_oid[] = {0x2b, 0x06, 0x01, 0x05, 0x05, 0x02};
    static const uint8_t ntlm_oid[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a};
    rdp_buffer oid_list;
    rdp_buffer oid_seq;
    rdp_buffer mech_types;
    rdp_buffer mech_token_body;
    rdp_buffer mech_token;
    rdp_buffer init_inner;
    rdp_buffer init_sequence;
    rdp_buffer neg_token_init;
    rdp_buffer application;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!ntlm_token && ntlm_token_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&oid_list);
    rdp_buffer_init(&oid_seq);
    rdp_buffer_init(&mech_types);
    rdp_buffer_init(&mech_token_body);
    rdp_buffer_init(&mech_token);
    rdp_buffer_init(&init_inner);
    rdp_buffer_init(&init_sequence);
    rdp_buffer_init(&neg_token_init);
    rdp_buffer_init(&application);

    status = rdp_der_write_oid(&oid_list, ntlm_oid, sizeof(ntlm_oid));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_wrap(&oid_seq, 0x30, &oid_list);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_context(&mech_types, 0, &oid_seq);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_octet_string(&mech_token_body, ntlm_token, ntlm_token_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_context(&mech_token, 2, &mech_token_body);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&init_inner, mech_types.data, mech_types.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&init_inner, mech_token.data, mech_token.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_wrap(&init_sequence, 0x30, &init_inner);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_context(&neg_token_init, 0, &init_sequence);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_oid(&application, spnego_oid, sizeof(spnego_oid));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&application, neg_token_init.data, neg_token_init.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_wrap(buffer, 0x60, &application);

    rdp_buffer_free(&application);
    rdp_buffer_free(&neg_token_init);
    rdp_buffer_free(&init_sequence);
    rdp_buffer_free(&init_inner);
    rdp_buffer_free(&mech_token);
    rdp_buffer_free(&mech_token_body);
    rdp_buffer_free(&mech_types);
    rdp_buffer_free(&oid_seq);
    rdp_buffer_free(&oid_list);
    return status;
}

/*
 * Build the NTLMv2 AUTHENTICATE message in one place so security-buffer
 * offsets, proof hashes, exported-session-key wrapping, and the final MIC stay
 * consistent. Secret inputs are consumed to derive protocol fields and must
 * not be traced or stored outside the caller-owned credential lifetime.
 */
librdp_status rdp_credssp_write_ntlm_authenticate(rdp_buffer* buffer,
                                                  const rdp_ntlm_challenge* challenge,
                                                  const char* username,
                                                  const char* password,
                                                  const char* domain,
                                                  const char* workstation,
                                                  uint64_t timestamp,
                                                  const uint8_t client_challenge[8],
                                                  const uint8_t exported_session_key[16],
                                                  rdp_ntlm_authenticate_result* result)
{
    static const uint8_t signature[] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
    static const uint8_t version[] = {10, 0, 0, 0, 0, 0, 0, 15};
    const size_t payload_offset = 72u;
    rdp_buffer domain_name;
    rdp_buffer user_name;
    rdp_buffer workstation_name;
    rdp_buffer blob;
    rdp_buffer lm_response;
    rdp_buffer nt_response;
    rdp_buffer encrypted_key;
    uint8_t nonce[8];
    uint8_t ntlm_v2_hash[16];
    uint8_t nt_proof[16];
    uint8_t lm_proof[16];
    uint8_t session_base_key[16];
    uint8_t session_key[16];
    uint32_t flags = 0;
    size_t lm_offset = 0;
    size_t nt_offset = 0;
    size_t domain_offset = 0;
    size_t user_offset = 0;
    size_t workstation_offset = 0;
    size_t key_offset = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !challenge || !username || !password ||
        (challenge->target_name_len > 0 && !challenge->target_name) ||
        (challenge->target_info_len > 0 && !challenge->target_info))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&domain_name);
    rdp_buffer_init(&user_name);
    rdp_buffer_init(&workstation_name);
    rdp_buffer_init(&blob);
    rdp_buffer_init(&lm_response);
    rdp_buffer_init(&nt_response);
    rdp_buffer_init(&encrypted_key);
    memset(nonce, 0, sizeof(nonce));
    memset(ntlm_v2_hash, 0, sizeof(ntlm_v2_hash));
    memset(nt_proof, 0, sizeof(nt_proof));
    memset(lm_proof, 0, sizeof(lm_proof));
    memset(session_base_key, 0, sizeof(session_base_key));
    memset(session_key, 0, sizeof(session_key));

    flags = rdp_ntlm_authenticate_flags(challenge);
    if ((flags & RDP_NTLM_NEGOTIATE_UNICODE) == 0 || (flags & RDP_NTLM_NEGOTIATE_NTLM) == 0 ||
        (flags & RDP_NTLM_NEGOTIATE_EXTENDED_SESSION) == 0)
    {
        status = LIBRDP_STATUS_UNSUPPORTED;
        goto out;
    }

    if (timestamp == 0)
        timestamp = rdp_ntlm_filetime_now();
    if (timestamp == 0)
    {
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto out;
    }
    if (client_challenge)
        memcpy(nonce, client_challenge, sizeof(nonce));
    else
    {
        status = rdp_ntlm_random_bytes(nonce, sizeof(nonce));
        if (status != LIBRDP_STATUS_OK)
            goto out;
    }

    status = rdp_ntlm_append_auth_domain(&domain_name, challenge, domain);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_append_utf16le_ascii(&user_name, username, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_append_utf16le_ascii(&workstation_name, workstation ? workstation : "", 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_ntlm_v2_hash(username, password, domain_name.data, domain_name.length, ntlm_v2_hash);
    if (status != LIBRDP_STATUS_OK)
        goto out;

    status = rdp_buffer_append_u32_le(&blob, 0x00000101u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&blob, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u64_le(&blob, timestamp);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&blob, nonce, sizeof(nonce));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&blob, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&blob, challenge->target_info, challenge->target_info_len);
    if (status == LIBRDP_STATUS_OK &&
        !rdp_ntlm_target_info_has_eol(challenge->target_info, challenge->target_info_len))
        status = rdp_buffer_append_u32_le(&blob, 0);
    if (status != LIBRDP_STATUS_OK)
        goto out;

    status = rdp_hmac_md5_parts(ntlm_v2_hash,
                                sizeof(ntlm_v2_hash),
                                challenge->server_challenge,
                                sizeof(challenge->server_challenge),
                                blob.data,
                                blob.length,
                                NULL,
                                0,
                                nt_proof);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&nt_response, nt_proof, sizeof(nt_proof));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&nt_response, blob.data, blob.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_hmac_md5_parts(ntlm_v2_hash,
                                    sizeof(ntlm_v2_hash),
                                    challenge->server_challenge,
                                    sizeof(challenge->server_challenge),
                                    nonce,
                                    sizeof(nonce),
                                    NULL,
                                    0,
                                    lm_proof);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&lm_response, lm_proof, sizeof(lm_proof));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&lm_response, nonce, sizeof(nonce));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_hmac_md5_parts(ntlm_v2_hash,
                                    sizeof(ntlm_v2_hash),
                                    nt_proof,
                                    sizeof(nt_proof),
                                    NULL,
                                    0,
                                    NULL,
                                    0,
                                    session_base_key);
    if (status != LIBRDP_STATUS_OK)
        goto out;

    if ((flags & RDP_NTLM_NEGOTIATE_KEY_EXCH) != 0)
    {
        rdp_ntlm_rc4_context rc4;

        memset(&rc4, 0, sizeof(rc4));
        if (exported_session_key)
            memcpy(session_key, exported_session_key, sizeof(session_key));
        else
        {
            status = rdp_ntlm_random_bytes(session_key, sizeof(session_key));
            if (status != LIBRDP_STATUS_OK)
                goto out;
        }
        status = rdp_buffer_append(&encrypted_key, session_key, sizeof(session_key));
        if (status != LIBRDP_STATUS_OK)
            goto out;

        /* CodeQL cpp/weak-cryptographic-algorithm false positive: RC4 is protocol-required legacy RDP/NTLM compatibility via OpenSSL EVP. */
        status = rdp_ntlm_rc4_init(&rc4, session_base_key, sizeof(session_base_key));
        if (status == LIBRDP_STATUS_OK)
        {
            /* CodeQL cpp/weak-cryptographic-algorithm false positive: RC4 is protocol-required legacy RDP/NTLM compatibility via OpenSSL EVP. */
            status = rdp_ntlm_rc4_crypt(&rc4, encrypted_key.data, encrypted_key.length);
        }
        OPENSSL_cleanse(&rc4, sizeof(rc4));
        if (status != LIBRDP_STATUS_OK)
            goto out;
    }
    else
    {
        memcpy(session_key, session_base_key, sizeof(session_key));
    }

    if (lm_response.length > 0xffffu || nt_response.length > 0xffffu || domain_name.length > 0xffffu ||
        user_name.length > 0xffffu || workstation_name.length > 0xffffu || encrypted_key.length > 0xffffu)
    {
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
        goto out;
    }

    lm_offset = payload_offset;
    nt_offset = lm_offset + lm_response.length;
    domain_offset = nt_offset + nt_response.length;
    user_offset = domain_offset + domain_name.length;
    workstation_offset = user_offset + user_name.length;
    key_offset = workstation_offset + workstation_name.length;
    if (key_offset > 0xffffffffu || encrypted_key.length > 0xffffffffu - key_offset)
    {
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
        goto out;
    }

    status = rdp_buffer_append(buffer, signature, sizeof(signature));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 3);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_ntlm_write_security_buffer(buffer, lm_response.length, lm_offset);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_ntlm_write_security_buffer(buffer, nt_response.length, nt_offset);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_ntlm_write_security_buffer(buffer, domain_name.length, domain_offset);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_ntlm_write_security_buffer(buffer, user_name.length, user_offset);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_ntlm_write_security_buffer(buffer, workstation_name.length, workstation_offset);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_ntlm_write_security_buffer(buffer, encrypted_key.length, key_offset);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, version, sizeof(version));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, lm_response.data, lm_response.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, nt_response.data, nt_response.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, domain_name.data, domain_name.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, user_name.data, user_name.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, workstation_name.data, workstation_name.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, encrypted_key.data, encrypted_key.length);
    if (status == LIBRDP_STATUS_OK && result)
    {
        result->flags = flags;
        memcpy(result->session_key, session_key, sizeof(result->session_key));
    }

out:
    if (domain_name.data)
        OPENSSL_cleanse(domain_name.data, domain_name.length);
    if (user_name.data)
        OPENSSL_cleanse(user_name.data, user_name.length);
    if (workstation_name.data)
        OPENSSL_cleanse(workstation_name.data, workstation_name.length);
    if (lm_response.data)
        OPENSSL_cleanse(lm_response.data, lm_response.length);
    if (nt_response.data)
        OPENSSL_cleanse(nt_response.data, nt_response.length);
    if (encrypted_key.data)
        OPENSSL_cleanse(encrypted_key.data, encrypted_key.length);
    if (blob.data)
        OPENSSL_cleanse(blob.data, blob.length);
    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(ntlm_v2_hash, sizeof(ntlm_v2_hash));
    OPENSSL_cleanse(nt_proof, sizeof(nt_proof));
    OPENSSL_cleanse(lm_proof, sizeof(lm_proof));
    OPENSSL_cleanse(session_base_key, sizeof(session_base_key));
    OPENSSL_cleanse(session_key, sizeof(session_key));
    rdp_buffer_free(&encrypted_key);
    rdp_buffer_free(&nt_response);
    rdp_buffer_free(&lm_response);
    rdp_buffer_free(&blob);
    rdp_buffer_free(&workstation_name);
    rdp_buffer_free(&user_name);
    rdp_buffer_free(&domain_name);
    return status;
}

librdp_status rdp_credssp_write_spnego_ntlm_authenticate(rdp_buffer* buffer,
                                                         const uint8_t* ntlm_token,
                                                         size_t ntlm_token_len)
{
    rdp_buffer token_body;
    rdp_buffer response_token;
    rdp_buffer response_sequence;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (!ntlm_token && ntlm_token_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&token_body);
    rdp_buffer_init(&response_token);
    rdp_buffer_init(&response_sequence);

    status = rdp_der_write_octet_string(&token_body, ntlm_token, ntlm_token_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_context(&response_token, 2, &token_body);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_wrap(&response_sequence, 0x30, &response_token);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_context(buffer, 1, &response_sequence);

    rdp_buffer_free(&response_sequence);
    rdp_buffer_free(&response_token);
    rdp_buffer_free(&token_body);
    return status;
}

librdp_status rdp_credssp_write_spnego_ntlm_challenge(rdp_buffer* buffer,
                                                      const uint8_t* ntlm_token,
                                                      size_t ntlm_token_len)
{
    return rdp_credssp_write_spnego_ntlm_authenticate(buffer, ntlm_token, ntlm_token_len);
}

/*
 * Encode a CredSSP TSRequest with optional token, auth-info, and public-key
 * fields. ASN.1 lengths are derived from validated buffers and credential-
 * bearing data must remain outside trace output.
 */
librdp_status rdp_credssp_write_ts_request(rdp_buffer* buffer,
                                           uint32_t version,
                                           const uint8_t* nego_token,
                                           size_t nego_token_len,
                                           const uint8_t* auth_info,
                                           size_t auth_info_len,
                                           const uint8_t* pub_key_auth,
                                           size_t pub_key_auth_len,
                                           const uint8_t* client_nonce,
                                           size_t client_nonce_len)
{
    rdp_buffer body;
    rdp_buffer field;
    rdp_buffer inner;
    rdp_buffer token_sequence;
    rdp_buffer token_list;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || version == 0 || (!nego_token && nego_token_len > 0) || (!auth_info && auth_info_len > 0) ||
        (!pub_key_auth && pub_key_auth_len > 0) || (!client_nonce && client_nonce_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&body);
    rdp_buffer_init(&field);
    rdp_buffer_init(&inner);
    rdp_buffer_init(&token_sequence);
    rdp_buffer_init(&token_list);

    status = rdp_der_write_integer(&field, version);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_context(&body, 0, &field);

    if (status == LIBRDP_STATUS_OK && nego_token_len > 0)
    {
        rdp_buffer_free(&field);
        rdp_buffer_init(&field);
        status = rdp_der_write_octet_string(&field, nego_token, nego_token_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_der_write_context(&inner, 0, &field);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_der_wrap(&token_sequence, 0x30, &inner);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_der_wrap(&token_list, 0x30, &token_sequence);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_der_write_context(&body, 1, &token_list);
    }

    if (status == LIBRDP_STATUS_OK && auth_info_len > 0)
    {
        rdp_buffer_free(&field);
        rdp_buffer_init(&field);
        status = rdp_der_write_octet_string(&field, auth_info, auth_info_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_der_write_context(&body, 2, &field);
    }

    if (status == LIBRDP_STATUS_OK && pub_key_auth_len > 0)
    {
        rdp_buffer_free(&field);
        rdp_buffer_init(&field);
        status = rdp_der_write_octet_string(&field, pub_key_auth, pub_key_auth_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_der_write_context(&body, 3, &field);
    }

    if (status == LIBRDP_STATUS_OK && client_nonce_len > 0)
    {
        rdp_buffer_free(&field);
        rdp_buffer_init(&field);
        status = rdp_der_write_octet_string(&field, client_nonce, client_nonce_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_der_write_context(&body, 5, &field);
    }

    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_wrap(buffer, 0x30, &body);

    rdp_buffer_free(&token_list);
    rdp_buffer_free(&token_sequence);
    rdp_buffer_free(&inner);
    rdp_buffer_free(&field);
    rdp_buffer_free(&body);
    return status;
}

librdp_status rdp_credssp_write_negotiate_request(rdp_buffer* buffer, const char* workstation, const char* domain)
{
    rdp_buffer ntlm;
    rdp_buffer spnego;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&ntlm);
    rdp_buffer_init(&spnego);

    status = rdp_credssp_write_ntlm_negotiate(&ntlm, workstation, domain);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_write_spnego_ntlm_negotiate(&spnego, ntlm.data, ntlm.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_write_ts_request(buffer, 6, spnego.data, spnego.length, NULL, 0, NULL, 0, NULL, 0);

    rdp_buffer_free(&spnego);
    rdp_buffer_free(&ntlm);
    return status;
}

static librdp_status rdp_der_read_tlv(rdp_stream* stream, uint8_t* tag, const uint8_t** value, size_t* length)
{
    const unsigned char* p = NULL;
    long parsed_len = 0;
    int parsed_tag = 0;
    int xclass = 0;
    int flags = 0;
    uint8_t encoded_tag = 0;
    size_t remaining = 0;
    size_t header_len = 0;

    if (!stream || !tag || !value || !length)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    remaining = rdp_stream_remaining(stream);
    if (remaining > LONG_MAX)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    p = stream->data + stream->position;
    flags = ASN1_get_object(&p, &parsed_len, &parsed_tag, &xclass, (long)remaining);
    if ((flags & 0x81) != 0 || parsed_len < 0 || parsed_tag > 30)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    header_len = (size_t)(p - (stream->data + stream->position));
    if (header_len > remaining || (size_t)parsed_len > remaining - header_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (xclass == V_ASN1_APPLICATION)
        encoded_tag = 0x40u;
    else if (xclass == V_ASN1_CONTEXT_SPECIFIC)
        encoded_tag = 0x80u;
    else if (xclass == V_ASN1_PRIVATE)
        encoded_tag = 0xc0u;
    else if (xclass != V_ASN1_UNIVERSAL)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & V_ASN1_CONSTRUCTED) != 0)
        encoded_tag |= 0x20u;
    encoded_tag |= (uint8_t)parsed_tag;
    stream->position += header_len;
    *tag = encoded_tag;
    *length = (size_t)parsed_len;
    return rdp_stream_read_bytes(stream, value, *length);
}

static librdp_status rdp_der_parse_integer(const uint8_t* data, size_t length, uint32_t* value)
{
    rdp_buffer body;
    rdp_buffer encoded;
    const unsigned char* p = NULL;
    ASN1_INTEGER* integer = NULL;
    uint64_t parsed = 0;
    librdp_status status = LIBRDP_STATUS_PROTOCOL_ERROR;

    if (!data || !value || length == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_buffer_init(&body);
    rdp_buffer_init(&encoded);
    if (rdp_buffer_append(&body, data, length) == LIBRDP_STATUS_OK &&
        rdp_der_wrap(&encoded, V_ASN1_INTEGER, &body) == LIBRDP_STATUS_OK)
    {
        p = encoded.data;
        integer = d2i_ASN1_INTEGER(NULL, &p, (long)encoded.length);
        if (integer && p == encoded.data + encoded.length &&
            ASN1_INTEGER_get_uint64(&parsed, integer) == 1 && parsed <= UINT32_MAX)
        {
            *value = (uint32_t)parsed;
            status = LIBRDP_STATUS_OK;
        }
    }
    ASN1_INTEGER_free(integer);
    rdp_buffer_free(&encoded);
    rdp_buffer_free(&body);
    return status;
}

static librdp_status rdp_credssp_parse_nego_tokens(const uint8_t* data,
                                                   size_t length,
                                                   rdp_credssp_ts_request* request)
{
    rdp_stream outer;
    rdp_stream list;
    rdp_stream item;
    rdp_stream context;
    uint8_t tag = 0;
    const uint8_t* value = NULL;
    size_t value_len = 0;

    rdp_stream_init(&outer, data, length);
    if (rdp_der_read_tlv(&outer, &tag, &value, &value_len) != LIBRDP_STATUS_OK || tag != 0x30)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&list, value, value_len);
    if (rdp_der_read_tlv(&list, &tag, &value, &value_len) != LIBRDP_STATUS_OK || tag != 0x30)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&item, value, value_len);
    if (rdp_der_read_tlv(&item, &tag, &value, &value_len) != LIBRDP_STATUS_OK || tag != 0xa0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&context, value, value_len);
    if (rdp_der_read_tlv(&context, &tag, &value, &value_len) != LIBRDP_STATUS_OK || tag != 0x04)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    request->nego_token = value;
    request->nego_token_len = value_len;
    return LIBRDP_STATUS_OK;
}

/*
 * Parse a CredSSP TSRequest ASN.1 sequence into borrowed token slices. Tags,
 * version, and optional fields are validated before output assignment so NLA
 * state never consumes partially trusted DER data.
 */
librdp_status rdp_credssp_parse_ts_request(const void* data, size_t length, rdp_credssp_ts_request* request)
{
    rdp_stream stream;
    rdp_stream sequence;
    uint8_t tag = 0;
    const uint8_t* value = NULL;
    size_t value_len = 0;

    if (!data || !request)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(request, 0, sizeof(*request));
    rdp_stream_init(&stream, data, length);
    if (rdp_der_read_tlv(&stream, &tag, &value, &value_len) != LIBRDP_STATUS_OK || tag != 0x30)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&sequence, value, value_len);
    while (rdp_stream_remaining(&sequence) > 0)
    {
        rdp_stream field;
        uint8_t inner_tag = 0;
        const uint8_t* inner = NULL;
        size_t inner_len = 0;

        if (rdp_der_read_tlv(&sequence, &tag, &value, &value_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        rdp_stream_init(&field, value, value_len);
        if (tag == 0xa0)
        {
            if (rdp_der_read_tlv(&field, &inner_tag, &inner, &inner_len) != LIBRDP_STATUS_OK || inner_tag != 0x02)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if (rdp_der_parse_integer(inner, inner_len, &request->version) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (tag == 0xa1)
        {
            if (rdp_credssp_parse_nego_tokens(value, value_len, request) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (tag == 0xa2)
        {
            if (rdp_der_read_tlv(&field, &inner_tag, &request->auth_info, &request->auth_info_len) !=
                    LIBRDP_STATUS_OK ||
                inner_tag != 0x04)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (tag == 0xa3)
        {
            if (rdp_der_read_tlv(&field, &inner_tag, &request->pub_key_auth, &request->pub_key_auth_len) !=
                    LIBRDP_STATUS_OK ||
                inner_tag != 0x04)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        else if (tag == 0xa4)
        {
            if (rdp_der_read_tlv(&field, &inner_tag, &inner, &inner_len) != LIBRDP_STATUS_OK || inner_tag != 0x02)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            if (rdp_der_parse_integer(inner, inner_len, &request->error_code) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            request->has_error_code = 1;
        }
        else if (tag == 0xa5)
        {
            if (rdp_der_read_tlv(&field, &inner_tag, &request->client_nonce, &request->client_nonce_len) !=
                    LIBRDP_STATUS_OK ||
                inner_tag != 0x04)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
    }
    return request->version > 0 ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_ntlm_read_security_buffer(const uint8_t* base,
                                                   size_t length,
                                                   size_t offset,
                                                   const uint8_t** value,
                                                   size_t* value_len)
{
    uint16_t len = 0;
    uint16_t max_len = 0;
    uint32_t data_offset = 0;

    if (!base || !value || !value_len || offset > length || length - offset < 8)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    len = rdp_read_u16_le_bytes(base + offset);
    max_len = rdp_read_u16_le_bytes(base + offset + 2u);
    data_offset = rdp_read_u32_le_bytes(base + offset + 4u);
    if (len > max_len || data_offset > length || (size_t)len > length - data_offset)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    *value = base + data_offset;
    *value_len = len;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_credssp_extract_ntlm_message(const void* token,
                                               size_t token_len,
                                               uint32_t message_type,
                                               const uint8_t** ntlm,
                                               size_t* ntlm_len)
{
    static const uint8_t signature[] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
    const uint8_t* bytes = (const uint8_t*)token;
    size_t i = 0;

    if (!token || !ntlm || !ntlm_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (message_type == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (token_len < sizeof(signature) + 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i <= token_len - sizeof(signature) - 4u; i++)
    {
        if (memcmp(bytes + i, signature, sizeof(signature)) == 0 &&
            rdp_read_u32_le_bytes(bytes + i + sizeof(signature)) == message_type)
        {
            *ntlm = bytes + i;
            *ntlm_len = token_len - i;
            return LIBRDP_STATUS_OK;
        }
    }
    return LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_credssp_extract_ntlm_challenge(const void* token,
                                                 size_t token_len,
                                                 const uint8_t** ntlm,
                                                 size_t* ntlm_len)
{
    return rdp_credssp_extract_ntlm_message(token, token_len, 2, ntlm, ntlm_len);
}

librdp_status rdp_credssp_parse_ntlm_negotiate(const void* data,
                                               size_t length,
                                               rdp_ntlm_negotiate* negotiate)
{
    static const uint8_t signature[] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
    const uint8_t* bytes = (const uint8_t*)data;

    if (!data || !negotiate)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 32u || memcmp(bytes, signature, sizeof(signature)) != 0 ||
        rdp_read_u32_le_bytes(bytes + 8u) != 1u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(negotiate, 0, sizeof(*negotiate));
    negotiate->flags = rdp_read_u32_le_bytes(bytes + 12u);
    if (rdp_ntlm_read_security_buffer(bytes, length, 16u, &negotiate->domain, &negotiate->domain_len) !=
            LIBRDP_STATUS_OK ||
        rdp_ntlm_read_security_buffer(bytes, length, 24u, &negotiate->workstation, &negotiate->workstation_len) !=
            LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_credssp_parse_ntlm_challenge(const void* data,
                                               size_t length,
                                               rdp_ntlm_challenge* challenge)
{
    static const uint8_t signature[] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
    const uint8_t* bytes = (const uint8_t*)data;

    if (!data || !challenge)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 48 || memcmp(bytes, signature, sizeof(signature)) != 0 ||
        rdp_read_u32_le_bytes(bytes + 8) != 2u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    memset(challenge, 0, sizeof(*challenge));
    if (rdp_ntlm_read_security_buffer(bytes, length, 12, &challenge->target_name, &challenge->target_name_len) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    challenge->flags = rdp_read_u32_le_bytes(bytes + 20);
    memcpy(challenge->server_challenge, bytes + 24, sizeof(challenge->server_challenge));
    if (rdp_ntlm_read_security_buffer(bytes, length, 40, &challenge->target_info, &challenge->target_info_len) !=
        LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_credssp_parse_ntlm_authenticate(const void* data,
                                                  size_t length,
                                                  rdp_ntlm_authenticate* authenticate)
{
    static const uint8_t signature[] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
    const uint8_t* bytes = (const uint8_t*)data;

    if (!data || !authenticate)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 64u || memcmp(bytes, signature, sizeof(signature)) != 0 ||
        rdp_read_u32_le_bytes(bytes + 8u) != 3u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(authenticate, 0, sizeof(*authenticate));
    if (rdp_ntlm_read_security_buffer(bytes, length, 12u, &authenticate->lm_response, &authenticate->lm_response_len) !=
            LIBRDP_STATUS_OK ||
        rdp_ntlm_read_security_buffer(bytes, length, 20u, &authenticate->nt_response, &authenticate->nt_response_len) !=
            LIBRDP_STATUS_OK ||
        rdp_ntlm_read_security_buffer(bytes, length, 28u, &authenticate->domain, &authenticate->domain_len) !=
            LIBRDP_STATUS_OK ||
        rdp_ntlm_read_security_buffer(bytes, length, 36u, &authenticate->username, &authenticate->username_len) !=
            LIBRDP_STATUS_OK ||
        rdp_ntlm_read_security_buffer(bytes, length, 44u, &authenticate->workstation, &authenticate->workstation_len) !=
            LIBRDP_STATUS_OK ||
        rdp_ntlm_read_security_buffer(bytes,
                                      length,
                                      52u,
                                      &authenticate->encrypted_session_key,
                                      &authenticate->encrypted_session_key_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    authenticate->flags = rdp_read_u32_le_bytes(bytes + 60u);
    return LIBRDP_STATUS_OK;
}

/*
 * Purpose: verify an NTLMv2 AUTHENTICATE message against the issued challenge,
 * expected username, and configured server password. Invariant: the exported
 * session key is decrypted only after the proof hash matches the server
 * challenge and target info. Failure policy: protocol mismatches leave result
 * zeroed and all derived secret material is cleansed before returning.
 */
librdp_status rdp_credssp_verify_ntlm_authenticate(const void* data,
                                                   size_t length,
                                                   const rdp_ntlm_challenge* challenge,
                                                   const char* expected_username,
                                                   const char* password,
                                                   rdp_ntlm_authenticate_result* result)
{
    rdp_ntlm_authenticate auth;
    rdp_buffer username_ascii;
    uint8_t ntlm_v2_hash[16];
    uint8_t expected_proof[16];
    uint8_t session_base_key[16];
    uint8_t session_key[16];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!challenge || !password || !result || !challenge->target_info || challenge->target_info_len == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));
    memset(ntlm_v2_hash, 0, sizeof(ntlm_v2_hash));
    memset(expected_proof, 0, sizeof(expected_proof));
    memset(session_base_key, 0, sizeof(session_base_key));
    memset(session_key, 0, sizeof(session_key));
    rdp_buffer_init(&username_ascii);
    status = rdp_credssp_parse_ntlm_authenticate(data, length, &auth);
    if (status == LIBRDP_STATUS_OK && auth.nt_response_len < 32u)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_utf16le_ascii_to_cstring(auth.username, auth.username_len, &username_ascii);
    if (status == LIBRDP_STATUS_OK && expected_username &&
        !rdp_ascii_equal_fold((const char*)username_ascii.data, expected_username))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_ntlm_v2_hash((const char*)username_ascii.data,
                                  password,
                                  auth.domain,
                                  auth.domain_len,
                                  ntlm_v2_hash);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_hmac_md5_parts(ntlm_v2_hash,
                                    sizeof(ntlm_v2_hash),
                                    challenge->server_challenge,
                                    sizeof(challenge->server_challenge),
                                    auth.nt_response + 16u,
                                    auth.nt_response_len - 16u,
                                    NULL,
                                    0,
                                    expected_proof);
    if (status == LIBRDP_STATUS_OK && CRYPTO_memcmp(auth.nt_response, expected_proof, sizeof(expected_proof)) != 0)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_hmac_md5_parts(ntlm_v2_hash,
                                    sizeof(ntlm_v2_hash),
                                    expected_proof,
                                    sizeof(expected_proof),
                                    NULL,
                                    0,
                                    NULL,
                                    0,
                                    session_base_key);
    if (status == LIBRDP_STATUS_OK)
    {
        if ((auth.flags & RDP_NTLM_NEGOTIATE_KEY_EXCH) != 0)
        {
            rdp_ntlm_rc4_context rc4;

            if (auth.encrypted_session_key_len != sizeof(session_key))
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
            else
            {
                memcpy(session_key, auth.encrypted_session_key, sizeof(session_key));
                status = rdp_ntlm_rc4_init(&rc4, session_base_key, sizeof(session_base_key));
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_ntlm_rc4_crypt(&rc4, session_key, sizeof(session_key));
                OPENSSL_cleanse(&rc4, sizeof(rc4));
            }
        }
        else
            memcpy(session_key, session_base_key, sizeof(session_key));
    }
    if (status == LIBRDP_STATUS_OK)
    {
        result->flags = auth.flags;
        memcpy(result->session_key, session_key, sizeof(result->session_key));
    }
    if (username_ascii.data)
        OPENSSL_cleanse(username_ascii.data, username_ascii.length);
    OPENSSL_cleanse(ntlm_v2_hash, sizeof(ntlm_v2_hash));
    OPENSSL_cleanse(expected_proof, sizeof(expected_proof));
    OPENSSL_cleanse(session_base_key, sizeof(session_base_key));
    OPENSSL_cleanse(session_key, sizeof(session_key));
    rdp_buffer_free(&username_ascii);
    return status;
}

librdp_status rdp_credssp_ntlm_security_init(rdp_ntlm_security_context* context,
                                             const rdp_ntlm_authenticate_result* authenticate)
{
    static const uint8_t client_sign_magic[] = "session key to client-to-server signing key magic constant";
    static const uint8_t server_sign_magic[] = "session key to server-to-client signing key magic constant";
    static const uint8_t client_seal_magic[] = "session key to client-to-server sealing key magic constant";
    static const uint8_t server_seal_magic[] = "session key to server-to-client sealing key magic constant";
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !authenticate)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(context, 0, sizeof(*context));
    context->flags = authenticate->flags;
    status = rdp_digest_parts(EVP_md5(),
                              authenticate->session_key,
                              sizeof(authenticate->session_key),
                              client_sign_magic,
                              sizeof(client_sign_magic),
                              NULL,
                              0,
                              context->client_signing_key,
                              sizeof(context->client_signing_key));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_digest_parts(EVP_md5(),
                                  authenticate->session_key,
                                  sizeof(authenticate->session_key),
                                  server_sign_magic,
                                  sizeof(server_sign_magic),
                                  NULL,
                                  0,
                                  context->server_signing_key,
                                  sizeof(context->server_signing_key));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_digest_parts(EVP_md5(),
                                  authenticate->session_key,
                                  sizeof(authenticate->session_key),
                                  client_seal_magic,
                                  sizeof(client_seal_magic),
                                  NULL,
                                  0,
                                  context->client_sealing_key,
                                  sizeof(context->client_sealing_key));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_digest_parts(EVP_md5(),
                                  authenticate->session_key,
                                  sizeof(authenticate->session_key),
                                  server_seal_magic,
                                  sizeof(server_seal_magic),
                                  NULL,
                                  0,
                                  context->server_sealing_key,
                                  sizeof(context->server_sealing_key));
    if (status != LIBRDP_STATUS_OK)
    {
        OPENSSL_cleanse(context, sizeof(*context));
        return status;
    }

    /* CodeQL cpp/weak-cryptographic-algorithm false positive: RC4 is protocol-required legacy RDP/NTLM compatibility via OpenSSL EVP. */
    status = rdp_ntlm_rc4_init(&context->send_rc4, context->client_sealing_key, sizeof(context->client_sealing_key));
    if (status == LIBRDP_STATUS_OK)
    {
        /* CodeQL cpp/weak-cryptographic-algorithm false positive: RC4 is protocol-required legacy RDP/NTLM compatibility via OpenSSL EVP. */
        status = rdp_ntlm_rc4_init(&context->recv_rc4, context->server_sealing_key, sizeof(context->server_sealing_key));
    }
    if (status != LIBRDP_STATUS_OK)
        OPENSSL_cleanse(context, sizeof(*context));
    return status;
}

librdp_status rdp_credssp_ntlm_server_security_init(rdp_ntlm_security_context* context,
                                                    const rdp_ntlm_authenticate_result* authenticate)
{
    rdp_ntlm_security_context base;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !authenticate)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&base, 0, sizeof(base));
    status = rdp_credssp_ntlm_security_init(&base, authenticate);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memset(context, 0, sizeof(*context));
    context->flags = base.flags;
    memcpy(context->client_signing_key, base.server_signing_key, sizeof(context->client_signing_key));
    memcpy(context->server_signing_key, base.client_signing_key, sizeof(context->server_signing_key));
    memcpy(context->client_sealing_key, base.server_sealing_key, sizeof(context->client_sealing_key));
    memcpy(context->server_sealing_key, base.client_sealing_key, sizeof(context->server_sealing_key));
    /* CodeQL cpp/weak-cryptographic-algorithm false positive: RC4 is protocol-required legacy RDP/NTLM compatibility via OpenSSL EVP. */
    status = rdp_ntlm_rc4_init(&context->send_rc4, context->client_sealing_key, sizeof(context->client_sealing_key));
    if (status == LIBRDP_STATUS_OK)
    {
        /* CodeQL cpp/weak-cryptographic-algorithm false positive: RC4 is protocol-required legacy RDP/NTLM compatibility via OpenSSL EVP. */
        status = rdp_ntlm_rc4_init(&context->recv_rc4,
                                   context->server_sealing_key,
                                   sizeof(context->server_sealing_key));
    }
    OPENSSL_cleanse(&base, sizeof(base));
    if (status != LIBRDP_STATUS_OK)
        OPENSSL_cleanse(context, sizeof(*context));
    return status;
}

librdp_status rdp_credssp_ntlm_wrap(rdp_ntlm_security_context* context,
                                    const void* data,
                                    size_t length,
                                    rdp_buffer* wrapped)
{
    const uint8_t* plain = (const uint8_t*)data;
    uint8_t seq[4];
    uint8_t digest[16];
    uint8_t checksum[8];
    size_t base = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || (!data && length > 0) || !wrapped)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    base = wrapped->length;
    rdp_write_u32_le_bytes(seq, context->send_seq);
    status = rdp_hmac_md5_parts(context->client_signing_key,
                                sizeof(context->client_signing_key),
                                seq,
                                sizeof(seq),
                                plain,
                                length,
                                NULL,
                                0,
                                digest);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_append(wrapped, digest, 16);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(wrapped, plain, length);
    if (status != LIBRDP_STATUS_OK)
    {
        OPENSSL_cleanse(digest, sizeof(digest));
        return status;
    }

    /* CodeQL cpp/weak-cryptographic-algorithm false positive: RC4 is protocol-required legacy RDP/NTLM compatibility via OpenSSL EVP. */
    status = rdp_ntlm_rc4_crypt(&context->send_rc4, wrapped->data + base + 16u, length);
    if (status != LIBRDP_STATUS_OK)
    {
        wrapped->length = base;
        OPENSSL_cleanse(digest, sizeof(digest));
        return status;
    }
    memcpy(checksum, digest, sizeof(checksum));

    /* CodeQL cpp/weak-cryptographic-algorithm false positive: RC4 is protocol-required legacy RDP/NTLM compatibility via OpenSSL EVP. */
    status = rdp_ntlm_rc4_crypt(&context->send_rc4, checksum, sizeof(checksum));
    if (status != LIBRDP_STATUS_OK)
    {
        wrapped->length = base;
        OPENSSL_cleanse(digest, sizeof(digest));
        OPENSSL_cleanse(checksum, sizeof(checksum));
        return status;
    }
    rdp_write_u32_le_bytes(wrapped->data + base, 1);
    memcpy(wrapped->data + base + 4u, checksum, sizeof(checksum));
    rdp_write_u32_le_bytes(wrapped->data + base + 12u, context->send_seq);
    context->send_seq++;
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(checksum, sizeof(checksum));
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_credssp_ntlm_unwrap(rdp_ntlm_security_context* context,
                                      const void* data,
                                      size_t length,
                                      rdp_buffer* plain)
{
    const uint8_t* wrapped = (const uint8_t*)data;
    uint8_t seq[4];
    uint8_t digest[16];
    uint8_t checksum[8];
    size_t base = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !data || !plain)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 16u || rdp_read_u32_le_bytes(wrapped) != 1u ||
        rdp_read_u32_le_bytes(wrapped + 12u) != context->recv_seq)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    base = plain->length;
    status = rdp_buffer_append(plain, wrapped + 16u, length - 16u);
    if (status != LIBRDP_STATUS_OK)
        return status;

    /* CodeQL cpp/weak-cryptographic-algorithm false positive: RC4 is protocol-required legacy RDP/NTLM compatibility via OpenSSL EVP. */
    status = rdp_ntlm_rc4_crypt(&context->recv_rc4, plain->data + base, plain->length - base);
    if (status != LIBRDP_STATUS_OK)
    {
        plain->length = base;
        return status;
    }
    rdp_write_u32_le_bytes(seq, context->recv_seq);
    status = rdp_hmac_md5_parts(context->server_signing_key,
                                sizeof(context->server_signing_key),
                                seq,
                                sizeof(seq),
                                plain->data + base,
                                plain->length - base,
                                NULL,
                                0,
                                digest);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memcpy(checksum, digest, sizeof(checksum));

    /* CodeQL cpp/weak-cryptographic-algorithm false positive: RC4 is protocol-required legacy RDP/NTLM compatibility via OpenSSL EVP. */
    status = rdp_ntlm_rc4_crypt(&context->recv_rc4, checksum, sizeof(checksum));
    if (status != LIBRDP_STATUS_OK)
    {
        plain->length = base;
        OPENSSL_cleanse(digest, sizeof(digest));
        OPENSSL_cleanse(checksum, sizeof(checksum));
        return status;
    }
    if (memcmp(wrapped + 4u, checksum, sizeof(checksum)) != 0)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    else
        context->recv_seq++;
    if (status != LIBRDP_STATUS_OK)
        plain->length = base;
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(checksum, sizeof(checksum));
    return status;
}

librdp_status rdp_credssp_encrypt_public_key_hash(rdp_ntlm_security_context* context,
                                                  const void* client_nonce,
                                                  size_t client_nonce_len,
                                                  const void* public_key,
                                                  size_t public_key_len,
                                                  rdp_buffer* encrypted)
{
    static const uint8_t magic[] = "CredSSP Client-To-Server Binding Hash";
    uint8_t hash[32];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !client_nonce || client_nonce_len != 32u || !public_key || public_key_len == 0 || !encrypted)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_digest_parts(EVP_sha256(),
                              magic,
                              sizeof(magic),
                              (const uint8_t*)client_nonce,
                              client_nonce_len,
                              (const uint8_t*)public_key,
                              public_key_len,
                              hash,
                              sizeof(hash));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_ntlm_wrap(context, hash, sizeof(hash), encrypted);
    OPENSSL_cleanse(hash, sizeof(hash));
    return status;
}

librdp_status rdp_credssp_verify_public_key_hash(rdp_ntlm_security_context* context,
                                                 const void* client_nonce,
                                                 size_t client_nonce_len,
                                                 const void* public_key,
                                                 size_t public_key_len,
                                                 const void* encrypted,
                                                 size_t encrypted_len)
{
    static const uint8_t magic[] = "CredSSP Server-To-Client Binding Hash";
    uint8_t expected[32];
    rdp_buffer plain;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !client_nonce || client_nonce_len != 32u || !public_key || public_key_len == 0 || !encrypted ||
        encrypted_len == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&plain);
    status = rdp_digest_parts(EVP_sha256(),
                              magic,
                              sizeof(magic),
                              (const uint8_t*)client_nonce,
                              client_nonce_len,
                              (const uint8_t*)public_key,
                              public_key_len,
                              expected,
                              sizeof(expected));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_ntlm_unwrap(context, encrypted, encrypted_len, &plain);
    if (status == LIBRDP_STATUS_OK &&
        (plain.length != sizeof(expected) || memcmp(plain.data, expected, sizeof(expected)) != 0))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (plain.data)
        OPENSSL_cleanse(plain.data, plain.length);
    OPENSSL_cleanse(expected, sizeof(expected));
    rdp_buffer_free(&plain);
    return status;
}

static librdp_status rdp_credssp_compute_public_key_hash(const uint8_t* magic,
                                                         size_t magic_len,
                                                         const void* client_nonce,
                                                         size_t client_nonce_len,
                                                         const void* public_key,
                                                         size_t public_key_len,
                                                         uint8_t output[32])
{
    if (!magic || magic_len == 0 || !client_nonce || client_nonce_len != 32u || !public_key ||
        public_key_len == 0 || !output)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_digest_parts(EVP_sha256(),
                            magic,
                            magic_len,
                            (const uint8_t*)client_nonce,
                            client_nonce_len,
                            (const uint8_t*)public_key,
                            public_key_len,
                            output,
                            32u);
}

librdp_status rdp_credssp_verify_client_public_key_hash(rdp_ntlm_security_context* context,
                                                        const void* client_nonce,
                                                        size_t client_nonce_len,
                                                        const void* public_key,
                                                        size_t public_key_len,
                                                        const void* encrypted,
                                                        size_t encrypted_len)
{
    static const uint8_t magic[] = "CredSSP Client-To-Server Binding Hash";
    uint8_t expected[32];
    rdp_buffer plain;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !encrypted || encrypted_len == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&plain);
    status = rdp_credssp_compute_public_key_hash(magic,
                                                 sizeof(magic),
                                                 client_nonce,
                                                 client_nonce_len,
                                                 public_key,
                                                 public_key_len,
                                                 expected);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_ntlm_unwrap(context, encrypted, encrypted_len, &plain);
    if (status == LIBRDP_STATUS_OK &&
        (plain.length != sizeof(expected) || CRYPTO_memcmp(plain.data, expected, sizeof(expected)) != 0))
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (plain.data)
        OPENSSL_cleanse(plain.data, plain.length);
    OPENSSL_cleanse(expected, sizeof(expected));
    rdp_buffer_free(&plain);
    return status;
}

librdp_status rdp_credssp_encrypt_server_public_key_hash(rdp_ntlm_security_context* context,
                                                         const void* client_nonce,
                                                         size_t client_nonce_len,
                                                         const void* public_key,
                                                         size_t public_key_len,
                                                         rdp_buffer* encrypted)
{
    static const uint8_t magic[] = "CredSSP Server-To-Client Binding Hash";
    uint8_t hash[32];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !encrypted)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_credssp_compute_public_key_hash(magic,
                                                 sizeof(magic),
                                                 client_nonce,
                                                 client_nonce_len,
                                                 public_key,
                                                 public_key_len,
                                                 hash);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_ntlm_wrap(context, hash, sizeof(hash), encrypted);
    OPENSSL_cleanse(hash, sizeof(hash));
    return status;
}

static librdp_status rdp_credssp_write_context_octet_string(rdp_buffer* body,
                                                            uint8_t index,
                                                            const uint8_t* data,
                                                            size_t length)
{
    rdp_buffer field;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!body || (!data && length > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&field);
    status = rdp_der_write_octet_string(&field, data, length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_context(body, index, &field);
    rdp_buffer_free(&field);
    return status;
}

librdp_status rdp_credssp_write_password_credentials(rdp_buffer* buffer,
                                                     const char* domain,
                                                     const char* username,
                                                     const char* password)
{
    rdp_buffer domain_utf16;
    rdp_buffer user_utf16;
    rdp_buffer password_utf16;
    rdp_buffer password_body;
    rdp_buffer password_sequence;
    rdp_buffer field;
    rdp_buffer credentials_body;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !username || !password)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&domain_utf16);
    rdp_buffer_init(&user_utf16);
    rdp_buffer_init(&password_utf16);
    rdp_buffer_init(&password_body);
    rdp_buffer_init(&password_sequence);
    rdp_buffer_init(&field);
    rdp_buffer_init(&credentials_body);

    status = rdp_append_utf16le_ascii(&domain_utf16, domain ? domain : "", 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_append_utf16le_ascii(&user_utf16, username, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_append_utf16le_ascii(&password_utf16, password, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_write_context_octet_string(&password_body, 0, domain_utf16.data, domain_utf16.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_write_context_octet_string(&password_body, 1, user_utf16.data, user_utf16.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_write_context_octet_string(&password_body, 2, password_utf16.data, password_utf16.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_wrap(&password_sequence, 0x30, &password_body);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_integer(&field, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_context(&credentials_body, 0, &field);
    if (status == LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&field);
        rdp_buffer_init(&field);
        status = rdp_der_write_octet_string(&field, password_sequence.data, password_sequence.length);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_context(&credentials_body, 1, &field);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_wrap(buffer, 0x30, &credentials_body);

    if (password_utf16.data)
        OPENSSL_cleanse(password_utf16.data, password_utf16.length);
    if (user_utf16.data)
        OPENSSL_cleanse(user_utf16.data, user_utf16.length);
    if (domain_utf16.data)
        OPENSSL_cleanse(domain_utf16.data, domain_utf16.length);
    rdp_buffer_free(&credentials_body);
    rdp_buffer_free(&field);
    rdp_buffer_free(&password_sequence);
    rdp_buffer_free(&password_body);
    rdp_buffer_free(&password_utf16);
    rdp_buffer_free(&user_utf16);
    rdp_buffer_free(&domain_utf16);
    return status;
}

librdp_status rdp_credssp_encrypt_password_credentials(rdp_ntlm_security_context* context,
                                                       const char* domain,
                                                       const char* username,
                                                       const char* password,
                                                       rdp_buffer* encrypted)
{
    rdp_buffer credentials;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !username || !password || !encrypted)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&credentials);
    status = rdp_credssp_write_password_credentials(&credentials, domain, username, password);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_ntlm_wrap(context, credentials.data, credentials.length, encrypted);
    if (credentials.data)
        OPENSSL_cleanse(credentials.data, credentials.length);
    rdp_buffer_free(&credentials);
    return status;
}

static librdp_status rdp_credssp_validate_password_sequence(const uint8_t* data, size_t length)
{
    rdp_stream outer;
    rdp_stream sequence;
    uint8_t outer_tag = 0;
    const uint8_t* sequence_data = NULL;
    size_t sequence_len = 0;
    uint8_t seen = 0;

    rdp_stream_init(&outer, data, length);
    if (rdp_der_read_tlv(&outer, &outer_tag, &sequence_data, &sequence_len) != LIBRDP_STATUS_OK ||
        outer_tag != 0x30 || rdp_stream_remaining(&outer) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&sequence, sequence_data, sequence_len);
    while (rdp_stream_remaining(&sequence) > 0)
    {
        rdp_stream field;
        uint8_t tag = 0;
        uint8_t inner_tag = 0;
        const uint8_t* value = NULL;
        const uint8_t* inner = NULL;
        size_t value_len = 0;
        size_t inner_len = 0;

        if (rdp_der_read_tlv(&sequence, &tag, &value, &value_len) != LIBRDP_STATUS_OK || tag < 0xa0 ||
            tag > 0xa2)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        rdp_stream_init(&field, value, value_len);
        if (rdp_der_read_tlv(&field, &inner_tag, &inner, &inner_len) != LIBRDP_STATUS_OK || inner_tag != 0x04 ||
            rdp_stream_remaining(&field) != 0 || (inner_len % 2u) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        seen |= (uint8_t)(1u << (tag - 0xa0u));
    }
    return seen == 0x07u ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_credssp_validate_password_credentials(const uint8_t* data, size_t length)
{
    rdp_stream outer;
    rdp_stream credentials;
    uint8_t tag = 0;
    uint8_t seen = 0;
    uint32_t credential_type = 0;
    const uint8_t* value = NULL;
    size_t value_len = 0;

    if (!data || length == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&outer, data, length);
    if (rdp_der_read_tlv(&outer, &tag, &value, &value_len) != LIBRDP_STATUS_OK || tag != 0x30 ||
        rdp_stream_remaining(&outer) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&credentials, value, value_len);
    while (rdp_stream_remaining(&credentials) > 0)
    {
        rdp_stream field;
        uint8_t inner_tag = 0;
        const uint8_t* inner = NULL;
        size_t inner_len = 0;

        if (rdp_der_read_tlv(&credentials, &tag, &value, &value_len) != LIBRDP_STATUS_OK ||
            (tag != 0xa0 && tag != 0xa1))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        rdp_stream_init(&field, value, value_len);
        if (tag == 0xa0)
        {
            if (rdp_der_read_tlv(&field, &inner_tag, &inner, &inner_len) != LIBRDP_STATUS_OK ||
                inner_tag != 0x02 ||
                rdp_der_parse_integer(inner, inner_len, &credential_type) != LIBRDP_STATUS_OK ||
                credential_type != 1u)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            seen |= 0x01u;
        }
        else
        {
            if (rdp_der_read_tlv(&field, &inner_tag, &inner, &inner_len) != LIBRDP_STATUS_OK ||
                inner_tag != 0x04 ||
                rdp_credssp_validate_password_sequence(inner, inner_len) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            seen |= 0x02u;
        }
        if (rdp_stream_remaining(&field) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return seen == 0x03u ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

void rdp_credssp_password_credentials_clear(rdp_credssp_password_credentials* credentials)
{
    if (!credentials)
        return;
    free(credentials->domain);
    free(credentials->username);
    if (credentials->password)
    {
        OPENSSL_cleanse(credentials->password, strlen(credentials->password));
        free(credentials->password);
    }
    memset(credentials, 0, sizeof(*credentials));
}

static librdp_status rdp_credssp_set_password_field(rdp_credssp_password_credentials* credentials,
                                                    uint8_t index,
                                                    const uint8_t* data,
                                                    size_t length)
{
    char** target = NULL;
    char* text = NULL;
    size_t text_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!credentials || (!data && length > 0) || (length % 2u) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (index == 0)
        target = &credentials->domain;
    else if (index == 1)
        target = &credentials->username;
    else if (index == 2)
        target = &credentials->password;
    else
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (*target)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_charset_utf16le_to_utf8_alloc(data, length, 0, &text, &text_len);
    (void)text_len;
    if (status != LIBRDP_STATUS_OK)
        return status;
    *target = text;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_credssp_parse_password_sequence(const uint8_t* data,
                                                         size_t length,
                                                         rdp_credssp_password_credentials* credentials)
{
    rdp_stream outer;
    rdp_stream sequence;
    uint8_t outer_tag = 0;
    uint8_t seen = 0;
    const uint8_t* sequence_data = NULL;
    size_t sequence_len = 0;

    rdp_stream_init(&outer, data, length);
    if (rdp_der_read_tlv(&outer, &outer_tag, &sequence_data, &sequence_len) != LIBRDP_STATUS_OK ||
        outer_tag != 0x30 || rdp_stream_remaining(&outer) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&sequence, sequence_data, sequence_len);
    while (rdp_stream_remaining(&sequence) > 0)
    {
        rdp_stream field;
        uint8_t tag = 0;
        uint8_t inner_tag = 0;
        uint8_t field_index = 0;
        const uint8_t* value = NULL;
        const uint8_t* inner = NULL;
        size_t value_len = 0;
        size_t inner_len = 0;
        librdp_status status = LIBRDP_STATUS_OK;

        if (rdp_der_read_tlv(&sequence, &tag, &value, &value_len) != LIBRDP_STATUS_OK || tag < 0xa0 ||
            tag > 0xa2)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        field_index = (uint8_t)(tag - 0xa0u);
        if ((seen & (uint8_t)(1u << field_index)) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        rdp_stream_init(&field, value, value_len);
        if (rdp_der_read_tlv(&field, &inner_tag, &inner, &inner_len) != LIBRDP_STATUS_OK || inner_tag != 0x04 ||
            rdp_stream_remaining(&field) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        status = rdp_credssp_set_password_field(credentials, field_index, inner, inner_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
        seen |= (uint8_t)(1u << field_index);
    }
    return seen == 0x07u ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

static librdp_status rdp_credssp_parse_password_credentials(const uint8_t* data,
                                                            size_t length,
                                                            rdp_credssp_password_credentials* credentials)
{
    rdp_stream outer;
    rdp_stream fields;
    uint8_t tag = 0;
    uint8_t seen = 0;
    uint32_t credential_type = 0;
    const uint8_t* value = NULL;
    size_t value_len = 0;

    if (!data || length == 0 || !credentials)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    memset(credentials, 0, sizeof(*credentials));
    rdp_stream_init(&outer, data, length);
    if (rdp_der_read_tlv(&outer, &tag, &value, &value_len) != LIBRDP_STATUS_OK || tag != 0x30 ||
        rdp_stream_remaining(&outer) != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_stream_init(&fields, value, value_len);
    while (rdp_stream_remaining(&fields) > 0)
    {
        rdp_stream field;
        uint8_t inner_tag = 0;
        const uint8_t* inner = NULL;
        size_t inner_len = 0;
        librdp_status status = LIBRDP_STATUS_OK;

        if (rdp_der_read_tlv(&fields, &tag, &value, &value_len) != LIBRDP_STATUS_OK ||
            (tag != 0xa0 && tag != 0xa1))
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        rdp_stream_init(&field, value, value_len);
        if (tag == 0xa0)
        {
            if ((seen & 0x01u) != 0 ||
                rdp_der_read_tlv(&field, &inner_tag, &inner, &inner_len) != LIBRDP_STATUS_OK ||
                inner_tag != 0x02 ||
                rdp_der_parse_integer(inner, inner_len, &credential_type) != LIBRDP_STATUS_OK ||
                credential_type != 1u)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            seen |= 0x01u;
        }
        else
        {
            if ((seen & 0x02u) != 0 ||
                rdp_der_read_tlv(&field, &inner_tag, &inner, &inner_len) != LIBRDP_STATUS_OK ||
                inner_tag != 0x04)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            status = rdp_credssp_parse_password_sequence(inner, inner_len, credentials);
            if (status != LIBRDP_STATUS_OK)
                return status;
            seen |= 0x02u;
        }
        if (rdp_stream_remaining(&field) != 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    return seen == 0x03u ? LIBRDP_STATUS_OK : LIBRDP_STATUS_PROTOCOL_ERROR;
}

librdp_status rdp_credssp_decrypt_password_credentials(rdp_ntlm_security_context* context,
                                                       const void* encrypted,
                                                       size_t encrypted_len)
{
    rdp_buffer plain;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !encrypted || encrypted_len == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&plain);
    status = rdp_credssp_ntlm_unwrap(context, encrypted, encrypted_len, &plain);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_validate_password_credentials(plain.data, plain.length);
    if (plain.data)
        OPENSSL_cleanse(plain.data, plain.length);
    rdp_buffer_free(&plain);
    return status;
}

librdp_status rdp_credssp_decrypt_password_credentials_ex(rdp_ntlm_security_context* context,
                                                          const void* encrypted,
                                                          size_t encrypted_len,
                                                          rdp_credssp_password_credentials* credentials)
{
    rdp_buffer plain;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !encrypted || encrypted_len == 0 || !credentials)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(credentials, 0, sizeof(*credentials));
    rdp_buffer_init(&plain);
    status = rdp_credssp_ntlm_unwrap(context, encrypted, encrypted_len, &plain);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_credssp_parse_password_credentials(plain.data, plain.length, credentials);
    if (status != LIBRDP_STATUS_OK)
        rdp_credssp_password_credentials_clear(credentials);
    if (plain.data)
        OPENSSL_cleanse(plain.data, plain.length);
    rdp_buffer_free(&plain);
    return status;
}
