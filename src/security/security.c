#include "security/security.h"

#include "common/stream.h"
#include "common/trace.h"
#include "protocol/mcs.h"
#include "protocol/x224.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <limits.h>
#include <string.h>

#define RDP_INFO_MOUSE 0x00000001u
#define RDP_INFO_DISABLE_CTRL_ALT_DEL 0x00000002u
#define RDP_INFO_AUTOLOGON 0x00000008u
#define RDP_INFO_UNICODE 0x00000010u
#define RDP_INFO_MAXIMIZE_SHELL 0x00000020u
#define RDP_INFO_ENABLE_WINDOWS_KEY 0x00000100u
#define RDP_INFO_FORCE_ENCRYPTED_CS_PDU 0x00004000u
#define RDP_INFO_LOGON_ERRORS 0x00010000u
#define RDP_INFO_MOUSE_HAS_WHEEL 0x00020000u

static const uint8_t rdp_pad1[40] = {
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
};

static const uint8_t rdp_pad2[48] = {
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
};

uint32_t rdp_security_protocol_mask(librdp_security_mode mode)
{
    switch (mode)
    {
        case LIBRDP_SECURITY_STANDARD:
            return RDP_X224_PROTOCOL_STANDARD;
        case LIBRDP_SECURITY_TLS:
            return RDP_X224_PROTOCOL_TLS;
        case LIBRDP_SECURITY_NLA:
            return RDP_X224_PROTOCOL_NLA;
        case LIBRDP_SECURITY_AUTO:
        default:
            return RDP_X224_PROTOCOL_TLS | RDP_X224_PROTOCOL_NLA;
    }
}

bool rdp_security_protocol_supported(uint32_t selected_protocol)
{
    return selected_protocol == RDP_X224_PROTOCOL_STANDARD || selected_protocol == RDP_X224_PROTOCOL_TLS ||
           selected_protocol == RDP_X224_PROTOCOL_NLA;
}

static size_t rdp_ascii_len(const char* text)
{
    return text ? strlen(text) : 0;
}

static librdp_status rdp_write_utf16le_text(rdp_buffer* buffer, const char* text)
{
    size_t i = 0;
    size_t length = rdp_ascii_len(text);

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length > 0x7fffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    for (i = 0; i < length; i++)
    {
        librdp_status status = rdp_buffer_append_u16_le(buffer, (uint16_t)(uint8_t)text[i]);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    return rdp_buffer_append_u16_le(buffer, 0);
}

static librdp_status rdp_security_write_extended_info(rdp_buffer* buffer)
{
    uint8_t time_zone[172];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(time_zone, 0, sizeof(time_zone));
    status = rdp_buffer_append_u16_le(buffer, 2);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, time_zone, sizeof(time_zone));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, 0);
    return status;
}

static librdp_status rdp_security_write_per_length(rdp_buffer* buffer, size_t length)
{
    if (!buffer || length > 0x7fffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (length > 0x7fu)
        return rdp_buffer_append_u16_be(buffer, (uint16_t)(length | 0x8000u));
    return rdp_buffer_append_u8(buffer, (uint8_t)length);
}

static librdp_status rdp_security_write_per_integer16(rdp_buffer* buffer, uint16_t value, uint16_t min)
{
    if (!buffer || value < min)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    return rdp_buffer_append_u16_be(buffer, (uint16_t)(value - min));
}

static librdp_status rdp_digest_concat(const EVP_MD* md,
                                       uint8_t* output,
                                       size_t output_len,
                                       const uint8_t* a,
                                       size_t a_len,
                                       const uint8_t* b,
                                       size_t b_len,
                                       const uint8_t* c,
                                       size_t c_len,
                                       const uint8_t* d,
                                       size_t d_len)
{
    EVP_MD_CTX* ctx = NULL;
    unsigned int got = 0;
    librdp_status status = LIBRDP_STATUS_PROTOCOL_ERROR;

    if (!md || !output || output_len > UINT_MAX || (!a && a_len > 0) || (!b && b_len > 0) ||
        (!c && c_len > 0) || (!d && d_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    ctx = EVP_MD_CTX_new();
    if (!ctx)
        return LIBRDP_STATUS_NO_MEMORY;
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1)
        goto out;
    if (a_len > 0 && EVP_DigestUpdate(ctx, a, a_len) != 1)
        goto out;
    if (b_len > 0 && EVP_DigestUpdate(ctx, b, b_len) != 1)
        goto out;
    if (c_len > 0 && EVP_DigestUpdate(ctx, c, c_len) != 1)
        goto out;
    if (d_len > 0 && EVP_DigestUpdate(ctx, d, d_len) != 1)
        goto out;
    if (EVP_DigestFinal_ex(ctx, output, &got) != 1 || got > output_len)
        goto out;
    status = LIBRDP_STATUS_OK;

out:
    EVP_MD_CTX_free(ctx);
    return status;
}

static librdp_status rdp_salted_hash(const uint8_t* secret,
                                     size_t secret_len,
                                     const uint8_t* label,
                                     size_t label_len,
                                     const uint8_t* random1,
                                     const uint8_t* random2,
                                     uint8_t output[16])
{
    uint8_t sha1[20];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!secret || secret_len != 48 || !label || !random1 || !random2 || !output)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_digest_concat(EVP_sha1(), sha1, sizeof(sha1), label, label_len, secret, secret_len, random1, 32,
                               random2, 32);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_digest_concat(EVP_md5(), output, 16, secret, secret_len, sha1, sizeof(sha1), NULL, 0, NULL, 0);
}

static librdp_status rdp_secret_triplet(const uint8_t* secret,
                                        const uint8_t* first,
                                        const uint8_t* second,
                                        const uint8_t* third,
                                        const uint8_t* random1,
                                        const uint8_t* random2,
                                        uint8_t output[48])
{
    librdp_status status = LIBRDP_STATUS_OK;

    status = rdp_salted_hash(secret, 48, first, 1, random1, random2, output);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_salted_hash(secret, 48, second, 2, random1, random2, output + 16);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_salted_hash(secret, 48, third, 3, random1, random2, output + 32);
    return status;
}

static librdp_status rdp_md5_key(const uint8_t* seed,
                                 const uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN],
                                 const uint8_t server_random[RDP_SECURITY_CLIENT_RANDOM_LEN],
                                 uint8_t output[16])
{
    return rdp_digest_concat(EVP_md5(), output, 16, seed, 16, client_random, RDP_SECURITY_CLIENT_RANDOM_LEN,
                             server_random, RDP_SECURITY_CLIENT_RANDOM_LEN, NULL, 0);
}

static void rdp_rc4_init(rdp_rc4_context* context, const uint8_t* key, size_t key_len)
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

static void rdp_rc4_crypt(rdp_rc4_context* context, uint8_t* data, size_t length)
{
    size_t n = 0;

    if (!context || (!data && length > 0))
        return;

    for (n = 0; n < length; n++)
    {
        uint8_t tmp = 0;
        uint8_t index = 0;
        context->i = (uint8_t)(context->i + 1u);
        context->j = (uint8_t)(context->j + context->s[context->i]);
        tmp = context->s[context->i];
        context->s[context->i] = context->s[context->j];
        context->s[context->j] = tmp;
        index = (uint8_t)(context->s[context->i] + context->s[context->j]);
        data[n] ^= context->s[index];
    }
}

static librdp_status rdp_security_apply_method(uint8_t* sign_key,
                                               uint8_t* encrypt_key,
                                               uint8_t* decrypt_key,
                                               size_t* key_len,
                                               uint32_t method)
{
    static const uint8_t salt[] = {0xd1, 0x26, 0x9e};

    if (!sign_key || !encrypt_key || !decrypt_key || !key_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    if (method == RDP_SECURITY_METHOD_128BIT)
    {
        *key_len = 16;
        return LIBRDP_STATUS_OK;
    }
    if (method == RDP_SECURITY_METHOD_56BIT)
    {
        sign_key[0] = salt[0];
        encrypt_key[0] = salt[0];
        decrypt_key[0] = salt[0];
        *key_len = 8;
        return LIBRDP_STATUS_OK;
    }
    if (method == RDP_SECURITY_METHOD_40BIT)
    {
        memcpy(sign_key, salt, 3);
        memcpy(encrypt_key, salt, 3);
        memcpy(decrypt_key, salt, 3);
        *key_len = 8;
        return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_UNSUPPORTED;
}

static librdp_status rdp_security_key_update(uint8_t key[16],
                                             const uint8_t update_key[16],
                                             size_t key_len,
                                             uint32_t method)
{
    uint8_t sha1[20];
    rdp_rc4_context rc4;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!key || !update_key || (key_len != 8u && key_len != 16u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_digest_concat(EVP_sha1(), sha1, sizeof(sha1), update_key, key_len, rdp_pad1, sizeof(rdp_pad1), key,
                               key_len, NULL, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_digest_concat(EVP_md5(), key, 16, update_key, key_len, rdp_pad2, sizeof(rdp_pad2), sha1,
                               sizeof(sha1), NULL, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;

    rdp_rc4_init(&rc4, key, key_len);
    rdp_rc4_crypt(&rc4, key, key_len);
    if (method == RDP_SECURITY_METHOD_40BIT)
    {
        static const uint8_t salt[] = {0xd1, 0x26, 0x9e};
        memcpy(key, salt, 3);
    }
    else if (method == RDP_SECURITY_METHOD_56BIT)
    {
        key[0] = 0xd1;
    }
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_security_write_header(rdp_buffer* buffer, uint16_t flags)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(buffer, flags);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u16_le(buffer, 0);
}

librdp_status rdp_security_write_exchange_pdu(rdp_buffer* buffer,
                                              const uint8_t* encrypted_client_random,
                                              size_t encrypted_client_random_len)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t pad[8];

    if (!buffer || (!encrypted_client_random && encrypted_client_random_len > 0) ||
        encrypted_client_random_len > 0xffffu - sizeof(pad))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(pad, 0, sizeof(pad));
    status = rdp_security_write_header(buffer, (uint16_t)(RDP_SEC_EXCHANGE_PKT | RDP_SEC_LICENSE_ENCRYPT_SC));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, (uint32_t)(encrypted_client_random_len + sizeof(pad)));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, encrypted_client_random, encrypted_client_random_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, pad, sizeof(pad));
    return status;
}

librdp_status rdp_security_write_client_info_pdu(rdp_buffer* buffer, const rdp_client_info* info)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_security_write_header(buffer, (uint16_t)RDP_SEC_INFO_PKT);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_security_write_client_info_body(buffer, info);
}

librdp_status rdp_security_write_client_info_body(rdp_buffer* buffer, const rdp_client_info* info)
{
    const size_t domain_len = info ? rdp_ascii_len(info->domain) : 0;
    const size_t username_len = info ? rdp_ascii_len(info->username) : 0;
    const size_t password_len = info ? rdp_ascii_len(info->password) : 0;
    const size_t shell_len = info ? rdp_ascii_len(info->alternate_shell) : 0;
    const size_t work_len = info ? rdp_ascii_len(info->working_dir) : 0;
    uint32_t flags = RDP_INFO_MOUSE | RDP_INFO_UNICODE | RDP_INFO_LOGON_ERRORS | RDP_INFO_MAXIMIZE_SHELL |
                     RDP_INFO_ENABLE_WINDOWS_KEY | RDP_INFO_DISABLE_CTRL_ALT_DEL | RDP_INFO_MOUSE_HAS_WHEEL |
                     RDP_INFO_FORCE_ENCRYPTED_CS_PDU;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || domain_len > 0x7fffu || username_len > 0x7fffu || password_len > 0x7fffu ||
        shell_len > 0x7fffu || work_len > 0x7fffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    if (info && info->password)
        flags |= RDP_INFO_AUTOLOGON;

    status = rdp_buffer_append_u32_le(buffer, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(buffer, flags);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)(domain_len * 2u));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)(username_len * 2u));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)(password_len * 2u));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)(shell_len * 2u));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(buffer, (uint16_t)(work_len * 2u));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_write_utf16le_text(buffer, info ? info->domain : NULL);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_write_utf16le_text(buffer, info ? info->username : NULL);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_write_utf16le_text(buffer, info ? info->password : NULL);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_write_utf16le_text(buffer, info ? info->alternate_shell : NULL);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_write_utf16le_text(buffer, info ? info->working_dir : NULL);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_extended_info(buffer);
    return status;
}

librdp_status rdp_security_standard_client_init(rdp_standard_security_context* context,
                                                uint32_t method,
                                                const uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN],
                                                const uint8_t server_random[RDP_SECURITY_CLIENT_RANDOM_LEN])
{
    static const uint8_t a[] = {'A'};
    static const uint8_t bb[] = {'B', 'B'};
    static const uint8_t ccc[] = {'C', 'C', 'C'};
    static const uint8_t x[] = {'X'};
    static const uint8_t yy[] = {'Y', 'Y'};
    static const uint8_t zzz[] = {'Z', 'Z', 'Z'};
    uint8_t pre_master[48];
    uint8_t master[48];
    uint8_t session_blob[48];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || !client_random || !server_random)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (method == 0 || method == RDP_SECURITY_METHOD_FIPS)
        return LIBRDP_STATUS_UNSUPPORTED;

    memset(context, 0, sizeof(*context));
    memcpy(pre_master, client_random, 24);
    memcpy(pre_master + 24, server_random, 24);

    status = rdp_secret_triplet(pre_master, a, bb, ccc, client_random, server_random, master);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_secret_triplet(master, x, yy, zzz, client_random, server_random, session_blob);
    if (status == LIBRDP_STATUS_OK)
    {
        memcpy(context->sign_key, session_blob, 16);
        status = rdp_md5_key(session_blob + 16, client_random, server_random, context->decrypt_key);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_md5_key(session_blob + 32, client_random, server_random, context->encrypt_key);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_apply_method(context->sign_key,
                                           context->encrypt_key,
                                           context->decrypt_key,
                                           &context->key_len,
                                           method);
    if (status == LIBRDP_STATUS_OK)
    {
        context->method = method;
        memcpy(context->encrypt_update_key, context->encrypt_key, sizeof(context->encrypt_update_key));
        memcpy(context->decrypt_update_key, context->decrypt_key, sizeof(context->decrypt_update_key));
        rdp_rc4_init(&context->encrypt_rc4, context->encrypt_key, context->key_len);
        rdp_rc4_init(&context->decrypt_rc4, context->decrypt_key, context->key_len);
    }

    OPENSSL_cleanse(pre_master, sizeof(pre_master));
    OPENSSL_cleanse(master, sizeof(master));
    OPENSSL_cleanse(session_blob, sizeof(session_blob));
    if (status != LIBRDP_STATUS_OK)
        rdp_security_standard_clear(context);
    return status;
}

void rdp_security_standard_clear(rdp_standard_security_context* context)
{
    if (!context)
        return;
    OPENSSL_cleanse(context, sizeof(*context));
}

librdp_status rdp_security_mac_signature(const rdp_standard_security_context* context,
                                         const void* data,
                                         size_t length,
                                         uint8_t signature[8])
{
    uint8_t len_le[4];
    uint8_t sha1[20];
    uint8_t md5[16];
    librdp_status status = LIBRDP_STATUS_OK;

    if (!context || (!data && length > 0) || !signature || length > UINT32_MAX ||
        (context->key_len != 8u && context->key_len != 16u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    len_le[0] = (uint8_t)(length & 0xffu);
    len_le[1] = (uint8_t)((length >> 8) & 0xffu);
    len_le[2] = (uint8_t)((length >> 16) & 0xffu);
    len_le[3] = (uint8_t)((length >> 24) & 0xffu);

    status = rdp_digest_concat(EVP_sha1(), sha1, sizeof(sha1), context->sign_key, context->key_len, rdp_pad1,
                               sizeof(rdp_pad1), len_le, sizeof(len_le), data, length);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_digest_concat(EVP_md5(), md5, sizeof(md5), context->sign_key, context->key_len, rdp_pad2,
                               sizeof(rdp_pad2), sha1, sizeof(sha1), NULL, 0);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memcpy(signature, md5, 8);
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_security_encrypt_payload(rdp_standard_security_context* context, void* data, size_t length)
{
    if (!context || (!data && length > 0) || (context->key_len != 8u && context->key_len != 16u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (context->encrypt_count >= 4096u)
    {
        librdp_status status = rdp_security_key_update(context->encrypt_key,
                                                       context->encrypt_update_key,
                                                       context->key_len,
                                                       context->method);
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_rc4_init(&context->encrypt_rc4, context->encrypt_key, context->key_len);
        context->encrypt_count = 0;
    }
    rdp_rc4_crypt(&context->encrypt_rc4, (uint8_t*)data, length);
    context->encrypt_count++;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_security_decrypt_payload(rdp_standard_security_context* context, void* data, size_t length)
{
    if (!context || (!data && length > 0) || (context->key_len != 8u && context->key_len != 16u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (context->decrypt_count >= 4096u)
    {
        librdp_status status = rdp_security_key_update(context->decrypt_key,
                                                       context->decrypt_update_key,
                                                       context->key_len,
                                                       context->method);
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_rc4_init(&context->decrypt_rc4, context->decrypt_key, context->key_len);
        context->decrypt_count = 0;
    }
    rdp_rc4_crypt(&context->decrypt_rc4, (uint8_t*)data, length);
    context->decrypt_count++;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_security_write_encrypted_pdu(rdp_buffer* buffer,
                                               rdp_standard_security_context* context,
                                               uint16_t flags,
                                               const void* payload,
                                               size_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t signature[8];
    size_t encrypted_offset = 0;

    if (!buffer || !context || (!payload && payload_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_security_mac_signature(context, payload, payload_len, signature);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_header(buffer, (uint16_t)(flags | RDP_SEC_ENCRYPT));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, signature, sizeof(signature));
    encrypted_offset = buffer->length;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, payload, payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_encrypt_payload(context, buffer->data + encrypted_offset, payload_len);
    return status;
}

librdp_status rdp_security_unwrap_pdu(rdp_standard_security_context* context,
                                      const void* data,
                                      size_t length,
                                      rdp_buffer* payload,
                                      uint16_t* flags)
{
    rdp_stream stream;
    uint16_t parsed_flags = 0;
    uint16_t flags_hi = 0;
    const uint8_t* signature = NULL;
    const uint8_t* body = NULL;
    size_t body_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data || !payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &parsed_flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &flags_hi) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (flags_hi != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if ((parsed_flags & RDP_SEC_ENCRYPT) != 0)
    {
        if (!context)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        if (rdp_stream_remaining(&stream) < 8u)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_stream_read_bytes(&stream, &signature, 8) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
    }

    body_len = rdp_stream_remaining(&stream);
    if (rdp_stream_read_bytes(&stream, &body, body_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_buffer_append(payload, body, body_len);
    if (status != LIBRDP_STATUS_OK)
        return status;

    if ((parsed_flags & RDP_SEC_ENCRYPT) != 0)
    {
        uint8_t expected[8];

        status = rdp_security_decrypt_payload(context, payload->data, payload->length);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if ((parsed_flags & RDP_SEC_SECURE_CHECKSUM) == 0)
        {
            status = rdp_security_mac_signature(context, payload->data, payload->length, expected);
            if (status != LIBRDP_STATUS_OK)
                return status;
            if (memcmp(signature, expected, sizeof(expected)) != 0)
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.security.signature.mismatch",
                                "flags=%u payload_len=%u",
                                parsed_flags,
                                (unsigned)payload->length);
        }
    }

    if (flags)
        *flags = parsed_flags;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_security_write_encrypted_client_info_pdu(rdp_buffer* buffer,
                                                           rdp_standard_security_context* context,
                                                           const rdp_client_info* info)
{
    rdp_buffer body;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || !context)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&body);
    status = rdp_security_write_client_info_body(&body, info);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_encrypted_pdu(buffer, context, (uint16_t)RDP_SEC_INFO_PKT, body.data, body.length);

    rdp_buffer_free(&body);
    return status;
}

librdp_status rdp_security_parse_client_info_pdu(const void* data, size_t length, rdp_client_info_summary* summary)
{
    rdp_stream stream;
    uint16_t flags = 0;
    uint16_t flags_hi = 0;
    size_t need = 0;

    if (!data || !summary)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(summary, 0, sizeof(*summary));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u16_le(&stream, &flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &flags_hi) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if ((flags & RDP_SEC_INFO_PKT) == 0 || flags_hi != 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_u32_le(&stream, &summary->code_page) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&stream, &summary->flags) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &summary->domain_bytes) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &summary->username_bytes) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &summary->password_bytes) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &summary->alternate_shell_bytes) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(&stream, &summary->working_dir_bytes) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    need = (size_t)summary->domain_bytes + summary->username_bytes + summary->password_bytes +
           summary->alternate_shell_bytes + summary->working_dir_bytes + 10u;
    if (rdp_stream_remaining(&stream) < need)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_security_write_send_data_request(rdp_buffer* buffer,
                                                   uint16_t user_id,
                                                   uint16_t channel_id,
                                                   const void* payload,
                                                   size_t payload_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || user_id < RDP_MCS_BASE_CHANNEL_ID || (!payload && payload_len > 0) || payload_len > 0x7fffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u8(buffer, (uint8_t)(25u << 2));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_per_integer16(buffer, user_id, (uint16_t)RDP_MCS_BASE_CHANNEL_ID);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_per_integer16(buffer, channel_id, 0);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(buffer, 0x70);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_per_length(buffer, payload_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(buffer, payload, payload_len);
    return status;
}
