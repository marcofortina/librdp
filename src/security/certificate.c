#include "security/security.h"

#include "common/stream.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define RDP_CERT_VERSION_1 1u
#define RDP_CERT_VERSION_2 2u
#define RDP_CERT_RSA_KEY_BLOB 0x0006u
#define RDP_RSA1_MAGIC 0x31415352u

static void rdp_reverse_copy(uint8_t* dst, const uint8_t* src, size_t length)
{
    size_t i = 0;

    for (i = 0; i < length; i++)
        dst[i] = src[length - 1u - i];
}

void rdp_security_public_key_clear(rdp_security_public_key* public_key)
{
    if (!public_key)
        return;
    free(public_key->owned_modulus_le);
    memset(public_key, 0, sizeof(*public_key));
}

static librdp_status rdp_security_parse_legacy_certificate(rdp_stream* stream,
                                                           rdp_security_public_key* public_key)
{
    rdp_stream blob;
    const uint8_t* blob_data = NULL;
    const uint8_t* modulus = NULL;
    uint32_t ignored32 = 0;
    uint16_t blob_type = 0;
    uint16_t blob_len = 0;
    uint32_t magic = 0;
    uint32_t key_len = 0;
    uint32_t bit_len = 0;
    uint32_t data_len = 0;
    uint32_t exponent = 0;

    if (rdp_stream_read_u32_le(stream, &ignored32) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(stream, &ignored32) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &blob_type) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u16_le(stream, &blob_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (blob_type != RDP_CERT_RSA_KEY_BLOB)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (blob_len < 28u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(stream, &blob_data, blob_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_stream_init(&blob, blob_data, blob_len);
    if (rdp_stream_read_u32_le(&blob, &magic) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&blob, &key_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&blob, &bit_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&blob, &data_len) != LIBRDP_STATUS_OK ||
        rdp_stream_read_u32_le(&blob, &exponent) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    if (magic != RDP_RSA1_MAGIC)
        return LIBRDP_STATUS_UNSUPPORTED;
    if (exponent == 0 || data_len == 0 || bit_len == 0)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_remaining(&blob) < (size_t)data_len + 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (key_len != data_len + 8u || bit_len > data_len * 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_read_bytes(&blob, &modulus, data_len) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rdp_stream_skip(&blob, 8) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    public_key->exponent = exponent;
    public_key->modulus_le = modulus;
    public_key->modulus_len = data_len;
    public_key->bit_len = bit_len;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_security_parse_x509_der(const uint8_t* data,
                                                 size_t length,
                                                 rdp_security_public_key* public_key)
{
    librdp_status status = LIBRDP_STATUS_PROTOCOL_ERROR;
    const unsigned char* cursor = data;
    X509* cert = NULL;
    EVP_PKEY* key = NULL;
    BIGNUM* n = NULL;
    BIGNUM* e = NULL;
    uint8_t* modulus_be = NULL;
    uint8_t* modulus_le = NULL;
    BN_ULONG exponent = 0;
    int modulus_len = 0;
    int bit_len = 0;

    if (!data || !public_key || length > (size_t)LONG_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    cert = d2i_X509(NULL, &cursor, (long)length);
    if (!cert)
        goto out;
    key = X509_get_pubkey(cert);
    if (!key)
        goto out;
    if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n) != 1 ||
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e) != 1)
    {
        status = LIBRDP_STATUS_UNSUPPORTED;
        goto out;
    }

    exponent = BN_get_word(e);
    if (exponent == (BN_ULONG)-1 || exponent > UINT32_MAX)
        goto out;
    modulus_len = BN_num_bytes(n);
    bit_len = BN_num_bits(n);
    if (modulus_len <= 0 || bit_len <= 0)
        goto out;

    modulus_be = (uint8_t*)malloc((size_t)modulus_len);
    modulus_le = (uint8_t*)malloc((size_t)modulus_len);
    if (!modulus_be || !modulus_le)
    {
        status = LIBRDP_STATUS_NO_MEMORY;
        goto out;
    }
    if (BN_bn2binpad(n, modulus_be, modulus_len) != modulus_len)
        goto out;
    rdp_reverse_copy(modulus_le, modulus_be, (size_t)modulus_len);

    public_key->exponent = (uint32_t)exponent;
    public_key->owned_modulus_le = modulus_le;
    public_key->modulus_le = modulus_le;
    public_key->modulus_len = (size_t)modulus_len;
    public_key->bit_len = (uint32_t)bit_len;
    modulus_le = NULL;
    status = LIBRDP_STATUS_OK;

out:
    free(modulus_le);
    if (modulus_be)
    {
        OPENSSL_cleanse(modulus_be, (size_t)modulus_len);
        free(modulus_be);
    }
    BN_free(e);
    BN_free(n);
    EVP_PKEY_free(key);
    X509_free(cert);
    return status;
}

static librdp_status rdp_security_parse_x509_chain(rdp_stream* stream, rdp_security_public_key* public_key)
{
    const uint32_t max_chain = 16;
    uint32_t count = 0;
    uint32_t i = 0;
    librdp_status status = LIBRDP_STATUS_PROTOCOL_ERROR;

    if (rdp_stream_read_u32_le(stream, &count) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (count == 0 || count > max_chain)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    for (i = 0; i < count; i++)
    {
        const uint8_t* blob = NULL;
        uint32_t blob_len = 0;

        if (rdp_stream_read_u32_le(stream, &blob_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (blob_len == 0)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (rdp_stream_read_bytes(stream, &blob, blob_len) != LIBRDP_STATUS_OK)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (i == 0)
            status = rdp_security_parse_x509_der(blob, blob_len, public_key);
    }

    return status;
}

librdp_status rdp_security_parse_server_certificate(const void* data,
                                                    size_t length,
                                                    rdp_security_public_key* public_key)
{
    rdp_stream stream;
    uint32_t version = 0;

    if (!data || !public_key)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(public_key, 0, sizeof(*public_key));
    rdp_stream_init(&stream, data, length);
    if (rdp_stream_read_u32_le(&stream, &version) != LIBRDP_STATUS_OK)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    version &= 0x7fffffffu;
    if (version == RDP_CERT_VERSION_1)
        return rdp_security_parse_legacy_certificate(&stream, public_key);
    if (version == RDP_CERT_VERSION_2)
        return rdp_security_parse_x509_chain(&stream, public_key);
    return LIBRDP_STATUS_UNSUPPORTED;
}

librdp_status rdp_security_generate_client_random(uint8_t random[RDP_SECURITY_CLIENT_RANDOM_LEN])
{
    if (!random)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (RAND_bytes(random, (int)RDP_SECURITY_CLIENT_RANDOM_LEN) != 1)
        return LIBRDP_STATUS_IO_ERROR;
    return LIBRDP_STATUS_OK;
}

librdp_status rdp_security_encrypt_client_random(const rdp_security_public_key* public_key,
                                                 const uint8_t random[RDP_SECURITY_CLIENT_RANDOM_LEN],
                                                 rdp_buffer* encrypted)
{
    librdp_status status = LIBRDP_STATUS_PROTOCOL_ERROR;
    uint8_t* modulus_be = NULL;
    uint8_t* output = NULL;
    BIGNUM* n = NULL;
    BIGNUM* e = NULL;
    OSSL_PARAM_BLD* builder = NULL;
    OSSL_PARAM* params = NULL;
    EVP_PKEY_CTX* key_ctx = NULL;
    EVP_PKEY_CTX* encrypt_ctx = NULL;
    EVP_PKEY* key = NULL;
    size_t output_len = 0;

    if (!public_key || !random || !encrypted)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!public_key->modulus_le || public_key->modulus_len <= RDP_SECURITY_CLIENT_RANDOM_LEN + 11u ||
        public_key->exponent == 0)
        return LIBRDP_STATUS_UNSUPPORTED;

    modulus_be = (uint8_t*)malloc(public_key->modulus_len);
    if (!modulus_be)
        return LIBRDP_STATUS_NO_MEMORY;
    rdp_reverse_copy(modulus_be, public_key->modulus_le, public_key->modulus_len);

    n = BN_bin2bn(modulus_be, (int)public_key->modulus_len, NULL);
    e = BN_new();
    builder = OSSL_PARAM_BLD_new();
    key_ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!n || !e || !builder || !key_ctx || BN_set_word(e, public_key->exponent) != 1)
        goto out;
    if (OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_N, n) != 1 ||
        OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_E, e) != 1)
        goto out;
    params = OSSL_PARAM_BLD_to_param(builder);
    if (!params)
        goto out;
    if (EVP_PKEY_fromdata_init(key_ctx) != 1 ||
        EVP_PKEY_fromdata(key_ctx, &key, EVP_PKEY_PUBLIC_KEY, params) != 1)
        goto out;

    encrypt_ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!encrypt_ctx)
        goto out;
    if (EVP_PKEY_encrypt_init(encrypt_ctx) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(encrypt_ctx, RSA_PKCS1_PADDING) != 1)
        goto out;
    if (EVP_PKEY_encrypt(encrypt_ctx, NULL, &output_len, random, RDP_SECURITY_CLIENT_RANDOM_LEN) != 1 ||
        output_len == 0)
        goto out;

    output = (uint8_t*)malloc(output_len);
    if (!output)
    {
        status = LIBRDP_STATUS_NO_MEMORY;
        goto out;
    }
    if (EVP_PKEY_encrypt(encrypt_ctx, output, &output_len, random, RDP_SECURITY_CLIENT_RANDOM_LEN) != 1)
        goto out;

    status = rdp_buffer_append(encrypted, output, output_len);

out:
    if (output)
        free(output);
    if (modulus_be)
    {
        OPENSSL_cleanse(modulus_be, public_key->modulus_len);
        free(modulus_be);
    }
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(encrypt_ctx);
    EVP_PKEY_CTX_free(key_ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(builder);
    BN_free(e);
    BN_free(n);
    return status;
}
