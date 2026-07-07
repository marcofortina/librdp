#include "nla/credssp.h"

#include "common/stream.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <ctype.h>
#include <limits.h>
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

typedef struct rdp_md4_context
{
    uint32_t state[4];
    uint64_t total_len;
    uint8_t block[64];
    size_t block_len;
} rdp_md4_context;

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

static librdp_status rdp_der_write_length(rdp_buffer* buffer, size_t length)
{
    uint8_t bytes[sizeof(size_t)];
    size_t count = 0;
    size_t value = length;
    size_t i = 0;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length < 0x80u)
        return rdp_buffer_append_u8(buffer, (uint8_t)length);

    while (value > 0)
    {
        bytes[sizeof(bytes) - 1u - count] = (uint8_t)(value & 0xffu);
        value >>= 8;
        count++;
    }
    if (count > 0x7fu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_buffer_append_u8(buffer, (uint8_t)(0x80u | count)) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_NO_MEMORY;
    for (i = sizeof(bytes) - count; i < sizeof(bytes); i++)
    {
        librdp_status status = rdp_buffer_append_u8(buffer, bytes[i]);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_der_wrap(rdp_buffer* output, uint8_t tag, const rdp_buffer* body)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!output || !body)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u8(output, tag);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_write_length(output, body->length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(output, body->data, body->length);
    return status;
}

static librdp_status rdp_der_write_integer(rdp_buffer* output, uint32_t value)
{
    rdp_buffer body;
    uint8_t bytes[5];
    size_t first = 0;
    size_t length = 4;
    librdp_status status = LIBRDP_STATUS_OK;

    rdp_buffer_init(&body);
    bytes[0] = (uint8_t)((value >> 24) & 0xffu);
    bytes[1] = (uint8_t)((value >> 16) & 0xffu);
    bytes[2] = (uint8_t)((value >> 8) & 0xffu);
    bytes[3] = (uint8_t)(value & 0xffu);
    while (first < 3u && bytes[first] == 0 && (bytes[first + 1u] & 0x80u) == 0)
        first++;
    if ((bytes[first] & 0x80u) != 0)
    {
        memmove(bytes + 1, bytes + first, 4u - first);
        bytes[0] = 0;
        length = 5u - first;
        first = 0;
    }
    else
    {
        length = 4u - first;
    }
    status = rdp_buffer_append(&body, bytes + first, length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_der_wrap(output, 0x02, &body);
    rdp_buffer_free(&body);
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
    size_t i = 0;
    size_t length = rdp_ascii_token_len(text);

    if (!buffer || (!text && length > 0) || length > 0x7fffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < length; i++)
    {
        uint8_t ch = (uint8_t)text[i];
        librdp_status status = LIBRDP_STATUS_OK;
        if (uppercase)
            ch = (uint8_t)toupper(ch);
        status = rdp_buffer_append_u16_le(buffer, ch);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return LIBRDP_STATUS_OK;
}

static uint32_t rdp_rotl32(uint32_t value, uint8_t bits)
{
    return (value << bits) | (value >> (32u - bits));
}

static void rdp_md4_init(rdp_md4_context* context)
{
    if (!context)
        return;
    context->state[0] = 0x67452301u;
    context->state[1] = 0xefcdab89u;
    context->state[2] = 0x98badcfeu;
    context->state[3] = 0x10325476u;
    context->total_len = 0;
    context->block_len = 0;
}

static void rdp_md4_step_f(uint32_t* a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint8_t s)
{
    *a = rdp_rotl32(*a + ((b & c) | (~b & d)) + x, s);
}

static void rdp_md4_step_g(uint32_t* a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint8_t s)
{
    *a = rdp_rotl32(*a + ((b & c) | (b & d) | (c & d)) + x + 0x5a827999u, s);
}

static void rdp_md4_step_h(uint32_t* a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint8_t s)
{
    *a = rdp_rotl32(*a + (b ^ c ^ d) + x + 0x6ed9eba1u, s);
}

static void rdp_md4_process(rdp_md4_context* context, const uint8_t block[64])
{
    uint32_t a = 0;
    uint32_t b = 0;
    uint32_t c = 0;
    uint32_t d = 0;
    uint32_t x[16];
    size_t i = 0;

    if (!context || !block)
        return;
    for (i = 0; i < 16u; i++)
        x[i] = rdp_read_u32_le_bytes(block + (i * 4u));

    a = context->state[0];
    b = context->state[1];
    c = context->state[2];
    d = context->state[3];

    rdp_md4_step_f(&a, b, c, d, x[0], 3);
    rdp_md4_step_f(&d, a, b, c, x[1], 7);
    rdp_md4_step_f(&c, d, a, b, x[2], 11);
    rdp_md4_step_f(&b, c, d, a, x[3], 19);
    rdp_md4_step_f(&a, b, c, d, x[4], 3);
    rdp_md4_step_f(&d, a, b, c, x[5], 7);
    rdp_md4_step_f(&c, d, a, b, x[6], 11);
    rdp_md4_step_f(&b, c, d, a, x[7], 19);
    rdp_md4_step_f(&a, b, c, d, x[8], 3);
    rdp_md4_step_f(&d, a, b, c, x[9], 7);
    rdp_md4_step_f(&c, d, a, b, x[10], 11);
    rdp_md4_step_f(&b, c, d, a, x[11], 19);
    rdp_md4_step_f(&a, b, c, d, x[12], 3);
    rdp_md4_step_f(&d, a, b, c, x[13], 7);
    rdp_md4_step_f(&c, d, a, b, x[14], 11);
    rdp_md4_step_f(&b, c, d, a, x[15], 19);

    rdp_md4_step_g(&a, b, c, d, x[0], 3);
    rdp_md4_step_g(&d, a, b, c, x[4], 5);
    rdp_md4_step_g(&c, d, a, b, x[8], 9);
    rdp_md4_step_g(&b, c, d, a, x[12], 13);
    rdp_md4_step_g(&a, b, c, d, x[1], 3);
    rdp_md4_step_g(&d, a, b, c, x[5], 5);
    rdp_md4_step_g(&c, d, a, b, x[9], 9);
    rdp_md4_step_g(&b, c, d, a, x[13], 13);
    rdp_md4_step_g(&a, b, c, d, x[2], 3);
    rdp_md4_step_g(&d, a, b, c, x[6], 5);
    rdp_md4_step_g(&c, d, a, b, x[10], 9);
    rdp_md4_step_g(&b, c, d, a, x[14], 13);
    rdp_md4_step_g(&a, b, c, d, x[3], 3);
    rdp_md4_step_g(&d, a, b, c, x[7], 5);
    rdp_md4_step_g(&c, d, a, b, x[11], 9);
    rdp_md4_step_g(&b, c, d, a, x[15], 13);

    rdp_md4_step_h(&a, b, c, d, x[0], 3);
    rdp_md4_step_h(&d, a, b, c, x[8], 9);
    rdp_md4_step_h(&c, d, a, b, x[4], 11);
    rdp_md4_step_h(&b, c, d, a, x[12], 15);
    rdp_md4_step_h(&a, b, c, d, x[2], 3);
    rdp_md4_step_h(&d, a, b, c, x[10], 9);
    rdp_md4_step_h(&c, d, a, b, x[6], 11);
    rdp_md4_step_h(&b, c, d, a, x[14], 15);
    rdp_md4_step_h(&a, b, c, d, x[1], 3);
    rdp_md4_step_h(&d, a, b, c, x[9], 9);
    rdp_md4_step_h(&c, d, a, b, x[5], 11);
    rdp_md4_step_h(&b, c, d, a, x[13], 15);
    rdp_md4_step_h(&a, b, c, d, x[3], 3);
    rdp_md4_step_h(&d, a, b, c, x[11], 9);
    rdp_md4_step_h(&c, d, a, b, x[7], 11);
    rdp_md4_step_h(&b, c, d, a, x[15], 15);

    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
}

static void rdp_md4_update(rdp_md4_context* context, const uint8_t* data, size_t length)
{
    size_t offset = 0;

    if (!context || (!data && length > 0))
        return;
    context->total_len += length;
    if (context->block_len > 0)
    {
        size_t needed = sizeof(context->block) - context->block_len;
        size_t take = length < needed ? length : needed;
        if (take > 0)
            memcpy(context->block + context->block_len, data, take);
        context->block_len += take;
        offset += take;
        if (context->block_len == sizeof(context->block))
        {
            rdp_md4_process(context, context->block);
            context->block_len = 0;
        }
    }
    while (length - offset >= sizeof(context->block))
    {
        rdp_md4_process(context, data + offset);
        offset += sizeof(context->block);
    }
    if (offset < length)
    {
        context->block_len = length - offset;
        memcpy(context->block, data + offset, context->block_len);
    }
}

static void rdp_md4_final(rdp_md4_context* context, uint8_t digest[16])
{
    uint8_t pad[64];
    uint8_t length_bytes[8];
    uint64_t bits = 0;
    size_t pad_len = 0;
    size_t i = 0;

    if (!context || !digest)
        return;
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    pad_len = context->block_len < 56u ? 56u - context->block_len : 120u - context->block_len;
    bits = context->total_len * 8u;
    for (i = 0; i < sizeof(length_bytes); i++)
        length_bytes[i] = (uint8_t)((bits >> (i * 8u)) & 0xffu);
    rdp_md4_update(context, pad, pad_len);
    rdp_md4_update(context, length_bytes, sizeof(length_bytes));
    for (i = 0; i < 4u; i++)
    {
        digest[(i * 4u) + 0u] = (uint8_t)(context->state[i] & 0xffu);
        digest[(i * 4u) + 1u] = (uint8_t)((context->state[i] >> 8) & 0xffu);
        digest[(i * 4u) + 2u] = (uint8_t)((context->state[i] >> 16) & 0xffu);
        digest[(i * 4u) + 3u] = (uint8_t)((context->state[i] >> 24) & 0xffu);
    }
}

static librdp_status rdp_md4_digest(const uint8_t* data, size_t length, uint8_t digest[16])
{
    rdp_md4_context context;

    if ((!data && length > 0) || !digest)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_md4_init(&context);
    rdp_md4_update(&context, data, length);
    rdp_md4_final(&context, digest);
    OPENSSL_cleanse(&context, sizeof(context));
    return LIBRDP_STATUS_OK;
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

static void rdp_ntlm_rc4_init(rdp_ntlm_rc4_context* context, const uint8_t* key, size_t key_len)
{
    size_t i = 0;
    uint8_t j = 0;

    if (!context || !key || key_len == 0)
        return;
    for (i = 0; i < 256u; i++)
        context->s[i] = (uint8_t)i;
    for (i = 0; i < 256u; i++)
    {
        uint8_t tmp = 0;
        j = (uint8_t)(j + context->s[i] + key[i % key_len]);
        tmp = context->s[i];
        context->s[i] = context->s[j];
        context->s[j] = tmp;
    }
    context->i = 0;
    context->j = 0;
}

static void rdp_ntlm_rc4_crypt(rdp_ntlm_rc4_context* context, uint8_t* data, size_t length)
{
    size_t i = 0;

    if (!context || (!data && length > 0))
        return;
    for (i = 0; i < length; i++)
    {
        uint8_t tmp = 0;
        uint8_t index = 0;
        context->i = (uint8_t)(context->i + 1u);
        context->j = (uint8_t)(context->j + context->s[context->i]);
        tmp = context->s[context->i];
        context->s[context->i] = context->s[context->j];
        context->s[context->j] = tmp;
        index = (uint8_t)(context->s[context->i] + context->s[context->j]);
        data[i] ^= context->s[index];
    }
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
        rdp_ntlm_rc4_init(&rc4, session_base_key, sizeof(session_base_key));
        rdp_ntlm_rc4_crypt(&rc4, encrypted_key.data, encrypted_key.length);
        OPENSSL_cleanse(&rc4, sizeof(rc4));
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

static librdp_status rdp_der_read_length(rdp_stream* stream, size_t* length)
{
    uint8_t first = 0;
    uint8_t count = 0;
    size_t value = 0;
    uint8_t i = 0;

    if (!stream || !length)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u8(stream, &first) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((first & 0x80u) == 0)
    {
        *length = first;
        return LIBRDP_STATUS_OK;
    }
    count = (uint8_t)(first & 0x7fu);
    if (count == 0 || count > sizeof(size_t) || rdp_stream_remaining(stream) < count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i < count; i++)
    {
        uint8_t byte = 0;
        if (rdp_stream_read_u8(stream, &byte) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        value = (value << 8) | byte;
    }
    *length = value;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_der_read_tlv(rdp_stream* stream, uint8_t* tag, const uint8_t** value, size_t* length)
{
    if (!stream || !tag || !value || !length)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rdp_stream_read_u8(stream, tag) != LIBRDP_STATUS_OK ||
        rdp_der_read_length(stream, length) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (*length > rdp_stream_remaining(stream))
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_stream_read_bytes(stream, value, *length);
}

static librdp_status rdp_der_parse_integer(const uint8_t* data, size_t length, uint32_t* value)
{
    size_t i = 0;
    uint32_t out = 0;

    if (!data || !value || length == 0 || length > 5)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (length == 5 && data[0] != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = (length == 5 ? 1u : 0u); i < length; i++)
        out = (out << 8) | data[i];
    *value = out;
    return LIBRDP_STATUS_OK;
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

librdp_status rdp_credssp_extract_ntlm_challenge(const void* token,
                                                 size_t token_len,
                                                 const uint8_t** ntlm,
                                                 size_t* ntlm_len)
{
    static const uint8_t signature[] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
    const uint8_t* bytes = (const uint8_t*)token;
    size_t i = 0;

    if (!token || !ntlm || !ntlm_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (token_len < sizeof(signature) + 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    for (i = 0; i <= token_len - sizeof(signature) - 4u; i++)
    {
        if (memcmp(bytes + i, signature, sizeof(signature)) == 0 &&
            rdp_read_u32_le_bytes(bytes + i + sizeof(signature)) == 2u)
        {
            *ntlm = bytes + i;
            *ntlm_len = token_len - i;
            return LIBRDP_STATUS_OK;
        }
    }
    return LIBRDP_STATUS_PROTOCOL_ERROR;
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

    rdp_ntlm_rc4_init(&context->send_rc4, context->client_sealing_key, sizeof(context->client_sealing_key));
    rdp_ntlm_rc4_init(&context->recv_rc4, context->server_sealing_key, sizeof(context->server_sealing_key));
    return LIBRDP_STATUS_OK;
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
    rdp_ntlm_rc4_crypt(&context->send_rc4, wrapped->data + base + 16u, length);
    memcpy(checksum, digest, sizeof(checksum));
    rdp_ntlm_rc4_crypt(&context->send_rc4, checksum, sizeof(checksum));
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
    rdp_ntlm_rc4_crypt(&context->recv_rc4, plain->data + base, plain->length - base);
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
    rdp_ntlm_rc4_crypt(&context->recv_rc4, checksum, sizeof(checksum));
    if (memcmp(wrapped + 4u, checksum, sizeof(checksum)) != 0)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    else
        context->recv_seq++;
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
