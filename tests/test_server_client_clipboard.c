/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic clipboard provider for client/server loopback smoke.
 * Coverage: bidirectional Unicode text, registered HTML, PNG, and streamed
 * file payloads across the public client API and application server host.
 * Bug classes: ownership races, request-correlation loss, payload corruption,
 * sparse-range corruption, duplicate requests, and provider dispatch outside
 * the server owner thread.
 * Determinism: payloads and request IDs are fixed and transport is loopback.
 */

#include "test_server_client_clipboard.h"

#include "graphics/gdi_image.h"

#include <librdp/clipboard.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CLIPBOARD_SHA256_BYTES 32u
#define CLIPBOARD_FILE_COUNT 4u
#define CLIPBOARD_FILE_TASK_COUNT (CLIPBOARD_FILE_COUNT * 2u)
#define CLIPBOARD_FILE_PATH_BYTES 192u
#define CLIPBOARD_FILE_RESPONSE_BYTES 96u
#define CLIPBOARD_FILE_DESCRIPTOR_REQUEST_ID 1009u
#define CLIPBOARD_FILE_REQUEST_ID_BASE 2000u
#define CLIPBOARD_FILE_STREAM_ID_BASE 3000u
#define CLIPBOARD_CLIENT_STREAM_ID_BASE 4000u
#define CLIPBOARD_SPARSE_MARKER_OFFSET 1048584u
#define CLIPBOARD_SPARSE_SIZE 1048648u
#define CLIPBOARD_LARGE_SIZE 2097409u

typedef enum clipboard_file_pattern
{
    CLIPBOARD_FILE_EMPTY = 0,
    CLIPBOARD_FILE_INLINE = 1,
    CLIPBOARD_FILE_SPARSE = 2,
    CLIPBOARD_FILE_PATTERN = 3
} clipboard_file_pattern;

typedef struct clipboard_file_definition
{
    const char* name;
    uint64_t size;
    uint64_t range_position;
    uint32_t range_requested;
    clipboard_file_pattern pattern;
    const uint8_t* bytes;
    size_t bytes_len;
    uint64_t bytes_offset;
    uint8_t seed;
} clipboard_file_definition;

static const uint8_t clipboard_client_text[] = {
    'c', 0u, 'l', 0u, 'i', 0u, 'e', 0u, 'n', 0u, 't', 0u, '-', 0u,
    0xe9u, 0u, '-', 0u, 0x3du, 0xd8u, 0u, 0xdeu, 0u, 0u,
};
static const uint8_t clipboard_server_text[] = {
    's', 0u, 'e', 0u, 'r', 0u, 'v', 0u, 'e', 0u, 'r', 0u, '-', 0u,
    0xacu, 0x20u, '-', 0u, 0x3du, 0xd8u, 0u, 0xdeu, 0u, 0u,
};
static const uint8_t clipboard_client_html[] =
    "Version:1.0\r\n"
    "StartHTML:0000000105\r\n"
    "EndHTML:0000000198\r\n"
    "StartFragment:0000000137\r\n"
    "EndFragment:0000000166\r\n"
    "<html><body><!--StartFragment-->"
    "<b>client-html-canary-853</b>"
    "<!--EndFragment--></body></html>";
static const uint8_t clipboard_server_html[] =
    "Version:1.0\r\n"
    "StartHTML:0000000105\r\n"
    "EndHTML:0000000198\r\n"
    "StartFragment:0000000137\r\n"
    "EndFragment:0000000166\r\n"
    "<html><body><!--StartFragment-->"
    "<i>server-html-canary-857</i>"
    "<!--EndFragment--></body></html>";
static const uint8_t clipboard_client_png[] = {
    0x89u, 0x50u, 0x4eu, 0x47u, 0x0du, 0x0au, 0x1au, 0x0au,
    0x00u, 0x00u, 0x00u, 0x0du, 0x49u, 0x48u, 0x44u, 0x52u,
    0x00u, 0x00u, 0x00u, 0x01u, 0x00u, 0x00u, 0x00u, 0x01u,
    0x08u, 0x06u, 0x00u, 0x00u, 0x00u, 0x1fu, 0x15u, 0xc4u,
    0x89u, 0x00u, 0x00u, 0x00u, 0x0du, 0x49u, 0x44u, 0x41u,
    0x54u, 0x78u, 0xdau, 0x63u, 0xf8u, 0xcfu, 0xc0u, 0xf0u,
    0x1fu, 0x00u, 0x05u, 0x00u, 0x01u, 0xffu, 0x56u, 0xc7u,
    0x2fu, 0x0du, 0x00u, 0x00u, 0x00u, 0x00u, 0x49u, 0x45u,
    0x4eu, 0x44u, 0xaeu, 0x42u, 0x60u, 0x82u,
};
static const uint8_t clipboard_server_png[] = {
    0x89u, 0x50u, 0x4eu, 0x47u, 0x0du, 0x0au, 0x1au, 0x0au,
    0x00u, 0x00u, 0x00u, 0x0du, 0x49u, 0x48u, 0x44u, 0x52u,
    0x00u, 0x00u, 0x00u, 0x01u, 0x00u, 0x00u, 0x00u, 0x01u,
    0x08u, 0x06u, 0x00u, 0x00u, 0x00u, 0x1fu, 0x15u, 0xc4u,
    0x89u, 0x00u, 0x00u, 0x00u, 0x0du, 0x49u, 0x44u, 0x41u,
    0x54u, 0x78u, 0xdau, 0x63u, 0x60u, 0xf8u, 0xcfu, 0xf0u,
    0x1fu, 0x00u, 0x04u, 0x01u, 0x01u, 0xffu, 0xaeu, 0xb5u,
    0x55u, 0xf5u, 0x00u, 0x00u, 0x00u, 0x00u, 0x49u, 0x45u,
    0x4eu, 0x44u, 0xaeu, 0x42u, 0x60u, 0x82u,
};
static const uint8_t clipboard_client_small_file[] =
    "client-file-canary-941:small-payload";
static const uint8_t clipboard_server_small_file[] =
    "server-file-canary-947:small-payload";
static const uint8_t clipboard_client_sparse_marker[] =
    "client-sparse-marker";
static const uint8_t clipboard_server_sparse_marker[] =
    "server-sparse-marker";
static const clipboard_file_definition clipboard_client_files[
    CLIPBOARD_FILE_COUNT] = {
        {
            "client-empty.bin",
            0u,
            0u,
            16u,
            CLIPBOARD_FILE_EMPTY,
            NULL,
            0u,
            0u,
            0u,
        },
        {
            "client-small.txt",
            sizeof(clipboard_client_small_file) - 1u,
            7u,
            19u,
            CLIPBOARD_FILE_INLINE,
            clipboard_client_small_file,
            sizeof(clipboard_client_small_file) - 1u,
            0u,
            0u,
        },
        {
            "client-sparse.bin",
            CLIPBOARD_SPARSE_SIZE,
            CLIPBOARD_SPARSE_MARKER_OFFSET - 8u,
            48u,
            CLIPBOARD_FILE_SPARSE,
            clipboard_client_sparse_marker,
            sizeof(clipboard_client_sparse_marker) - 1u,
            CLIPBOARD_SPARSE_MARKER_OFFSET,
            0u,
        },
        {
            "client-large.bin",
            CLIPBOARD_LARGE_SIZE,
            CLIPBOARD_LARGE_SIZE - 64u,
            64u,
            CLIPBOARD_FILE_PATTERN,
            NULL,
            0u,
            0u,
            0x31u,
        },
    };
static const clipboard_file_definition clipboard_server_files[
    CLIPBOARD_FILE_COUNT] = {
        {
            "server-empty.bin",
            0u,
            0u,
            16u,
            CLIPBOARD_FILE_EMPTY,
            NULL,
            0u,
            0u,
            0u,
        },
        {
            "server-small.txt",
            sizeof(clipboard_server_small_file) - 1u,
            6u,
            21u,
            CLIPBOARD_FILE_INLINE,
            clipboard_server_small_file,
            sizeof(clipboard_server_small_file) - 1u,
            0u,
            0u,
        },
        {
            "server-sparse.bin",
            CLIPBOARD_SPARSE_SIZE,
            CLIPBOARD_SPARSE_MARKER_OFFSET - 8u,
            48u,
            CLIPBOARD_FILE_SPARSE,
            clipboard_server_sparse_marker,
            sizeof(clipboard_server_sparse_marker) - 1u,
            CLIPBOARD_SPARSE_MARKER_OFFSET,
            0u,
        },
        {
            "server-large.bin",
            CLIPBOARD_LARGE_SIZE,
            CLIPBOARD_LARGE_SIZE - 64u,
            64u,
            CLIPBOARD_FILE_PATTERN,
            NULL,
            0u,
            0u,
            0xa7u,
        },
    };
static const uint8_t clipboard_client_png_pixels_sha256[
    CLIPBOARD_SHA256_BYTES] = {
        0xb7u, 0xd1u, 0xb3u, 0xa1u, 0x10u, 0x4cu, 0xc8u, 0x6bu,
        0x1cu, 0xeau, 0x31u, 0x07u, 0x93u, 0xcfu, 0x77u, 0x70u,
        0x02u, 0xdbu, 0x05u, 0x17u, 0x28u, 0x1du, 0x13u, 0x5au,
        0x02u, 0xdeu, 0x07u, 0x9bu, 0x0eu, 0xa8u, 0x7cu, 0x23u,
    };
static const uint8_t clipboard_server_png_pixels_sha256[
    CLIPBOARD_SHA256_BYTES] = {
        0x7au, 0x7bu, 0xf4u, 0x54u, 0xc5u, 0xf3u, 0xcbu, 0x1bu,
        0x9du, 0x9au, 0x20u, 0xf8u, 0x14u, 0x17u, 0xf9u, 0x8du,
        0x97u, 0x6fu, 0xe3u, 0xb3u, 0xddu, 0x52u, 0xc1u, 0xb9u,
        0x96u, 0x8fu, 0x02u, 0xe8u, 0x9eu, 0x7eu, 0x8au, 0x2fu,
    };
static const server_client_clipboard_profile clipboard_text_profile = {
    LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT,
    NULL,
    "text/plain;charset=utf-8",
    clipboard_client_text,
    sizeof(clipboard_client_text),
    NULL,
    clipboard_server_text,
    sizeof(clipboard_server_text),
    NULL,
    NULL,
    0,
};
static const server_client_clipboard_profile clipboard_html_profile = {
    LIBRDP_CLIPBOARD_FORMAT_HTML,
    LIBRDP_CLIPBOARD_FORMAT_NAME_HTML,
    "text/html",
    clipboard_client_html,
    sizeof(clipboard_client_html) - 1u,
    NULL,
    clipboard_server_html,
    sizeof(clipboard_server_html) - 1u,
    NULL,
    "server-html-canary-857",
    0,
};
static const server_client_clipboard_profile clipboard_png_profile = {
    LIBRDP_CLIPBOARD_FORMAT_PNG,
    LIBRDP_CLIPBOARD_FORMAT_NAME_PNG,
    "image/png",
    clipboard_client_png,
    sizeof(clipboard_client_png),
    clipboard_client_png_pixels_sha256,
    clipboard_server_png,
    sizeof(clipboard_server_png),
    clipboard_server_png_pixels_sha256,
    NULL,
    0,
};
static const server_client_clipboard_profile clipboard_files_profile = {
    LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW,
    LIBRDP_CLIPBOARD_FORMAT_NAME_FILEGROUPDESCRIPTORW,
    "text/uri-list",
    NULL,
    0u,
    NULL,
    NULL,
    0u,
    NULL,
    "file-canary",
    1,
};

struct server_client_clipboard_provider
{
    server_platform_clipboard_sink sink;
    server_platform_clipboard_request pending_request;
    server_platform_clipboard_file_request pending_file_request;
    const server_client_clipboard_profile* profile;
    uint8_t* server_file_group;
    size_t server_file_group_len;
    char client_directory[CLIPBOARD_FILE_PATH_BYTES];
    char client_paths[CLIPBOARD_FILE_COUNT][CLIPBOARD_FILE_PATH_BYTES];
    librdp_clipboard_file client_file_entries[CLIPBOARD_FILE_COUNT];
    atomic_uint offers;
    atomic_uint local_requests;
    atomic_uint remote_requests;
    atomic_uint remote_data;
    atomic_uint local_file_requests;
    atomic_uint remote_file_requests;
    atomic_uint remote_file_responses;
    atomic_uint client_format_events;
    atomic_uint client_data_events;
    atomic_uint client_request_events;
    atomic_uint client_file_responses;
    atomic_uint failures;
    unsigned int remote_file_task;
    unsigned int local_file_task;
    unsigned int client_file_task;
    int request_pending;
    int file_request_pending;
    int client_data_requested;
};

const server_client_clipboard_profile*
server_client_clipboard_profile_by_name(const char* name)
{
    if (!name)
        return NULL;
    if (strcmp(name, "clipboard-text") == 0)
        return &clipboard_text_profile;
    if (strcmp(name, "clipboard-html") == 0)
        return &clipboard_html_profile;
    if (strcmp(name, "clipboard-png") == 0)
        return &clipboard_png_profile;
    if (strcmp(name, "clipboard-files") == 0)
        return &clipboard_files_profile;
    return NULL;
}

/*
 * Decode image payloads before comparing their canonical BGRA32 pixel digest.
 * Builds without an image backend retain the wire-integrity check, while full
 * builds exercise the same bounded decoder used by the graphics runtime.
 */
static int clipboard_decoded_hash_matches(
    const uint8_t* data,
    size_t data_len,
    const uint8_t expected[CLIPBOARD_SHA256_BYTES])
{
    if (!expected)
        return 1;
#if defined(RDP_HAVE_PNG) || defined(RDP_HAVE_QUARTZ)
    rdp_gdi_image image;
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0u;
    size_t pixels_len = 0u;
    int matched = 0;

    rdp_gdi_image_init(&image);
    if (rdp_gdi_image_decode(data, data_len, &image) !=
            LIBRDP_STATUS_OK ||
        !image.pixels || image.width != 1u || image.height != 1u ||
        image.stride > SIZE_MAX / image.height)
    {
        rdp_gdi_image_clear(&image);
        return 0;
    }
    pixels_len = image.stride * image.height;
    if (EVP_Digest(image.pixels,
                   pixels_len,
                   digest,
                   &digest_len,
                   EVP_sha256(),
                   NULL) == 1 &&
        digest_len == CLIPBOARD_SHA256_BYTES &&
        CRYPTO_memcmp(digest,
                      expected,
                      CLIPBOARD_SHA256_BYTES) == 0)
        matched = 1;
    rdp_gdi_image_clear(&image);
    return matched;
#else
    (void)data;
    (void)data_len;
    return 1;
#endif
}

static int clipboard_payload_matches(
    const uint8_t* data,
    size_t data_len,
    const uint8_t* expected,
    size_t expected_len,
    const uint8_t* expected_decoded_sha256)
{
    if ((!data && data_len > 0u) ||
        (!expected && expected_len > 0u) ||
        data_len != expected_len ||
        (data_len > 0u &&
         memcmp(data, expected, data_len) != 0))
        return 0;
    return clipboard_decoded_hash_matches(data,
                                          data_len,
                                          expected_decoded_sha256);
}

int server_client_clipboard_profile_validate_server_data(
    const server_client_clipboard_profile* profile,
    const uint8_t* data,
    size_t data_len)
{
    return profile &&
           clipboard_payload_matches(
               data,
               data_len,
               profile->server_data,
               profile->server_data_len,
               profile->server_decoded_sha256);
}

int server_client_clipboard_profile_is_file_transfer(
    const server_client_clipboard_profile* profile)
{
    return profile && profile->file_transfer;
}

static size_t clipboard_file_fill(
    const clipboard_file_definition* definition,
    uint64_t position,
    uint32_t requested,
    uint8_t* output,
    size_t output_capacity)
{
    uint64_t available = 0u;
    size_t take = 0u;
    size_t index = 0u;

    if (!definition || (!output && output_capacity > 0u) ||
        position >= definition->size)
        return 0u;
    available = definition->size - position;
    take = available < (uint64_t)requested
               ? (size_t)available
               : (size_t)requested;
    if (take > output_capacity)
        return SIZE_MAX;
    memset(output, 0, take);
    if (definition->pattern == CLIPBOARD_FILE_PATTERN)
    {
        for (index = 0u; index < take; index++)
        {
            uint64_t absolute = position + (uint64_t)index;

            output[index] =
                (uint8_t)((absolute * 37u + definition->seed) & 0xffu);
        }
    }
    else if ((definition->pattern == CLIPBOARD_FILE_INLINE ||
              definition->pattern == CLIPBOARD_FILE_SPARSE) &&
             definition->bytes && definition->bytes_len > 0u)
    {
        uint64_t source_start = definition->bytes_offset;
        uint64_t source_end =
            source_start + (uint64_t)definition->bytes_len;
        uint64_t range_end = position + (uint64_t)take;
        uint64_t overlap_start =
            position > source_start ? position : source_start;
        uint64_t overlap_end =
            range_end < source_end ? range_end : source_end;

        if (overlap_start < overlap_end)
        {
            size_t destination_offset =
                (size_t)(overlap_start - position);
            size_t source_offset =
                (size_t)(overlap_start - source_start);
            size_t overlap = (size_t)(overlap_end - overlap_start);

            memcpy(output + destination_offset,
                   definition->bytes + source_offset,
                   overlap);
        }
    }
    return take;
}

static void clipboard_write_u64_le(uint8_t output[8], uint64_t value)
{
    unsigned int index = 0u;

    for (index = 0u; index < 8u; index++)
        output[index] = (uint8_t)(value >> (index * 8u));
}

static int clipboard_file_response_matches(
    const clipboard_file_definition* definition,
    uint32_t flags,
    uint64_t position,
    uint32_t requested,
    const uint8_t* data,
    size_t data_len)
{
    uint8_t expected[CLIPBOARD_FILE_RESPONSE_BYTES];
    size_t expected_len = 0u;

    if (!definition || (!data && data_len > 0u))
        return 0;
    if (flags == LIBRDP_CLIPBOARD_FILECONTENTS_SIZE)
    {
        clipboard_write_u64_le(expected, definition->size);
        expected_len = 8u;
    }
    else if (flags == LIBRDP_CLIPBOARD_FILECONTENTS_RANGE)
    {
        expected_len = clipboard_file_fill(definition,
                                           position,
                                           requested,
                                           expected,
                                           sizeof(expected));
        if (expected_len == SIZE_MAX)
            return 0;
    }
    else
    {
        return 0;
    }
    return data_len == expected_len &&
           (expected_len == 0u ||
            memcmp(data, expected, expected_len) == 0);
}

static void clipboard_file_task(
    const clipboard_file_definition* definitions,
    unsigned int task,
    int32_t* file_index,
    uint32_t* flags,
    uint64_t* position,
    uint32_t* requested)
{
    unsigned int index = task / 2u;

    *file_index = (int32_t)index;
    if ((task & 1u) == 0u)
    {
        *flags = LIBRDP_CLIPBOARD_FILECONTENTS_SIZE;
        *position = 0u;
        *requested = 8u;
    }
    else
    {
        *flags = LIBRDP_CLIPBOARD_FILECONTENTS_RANGE;
        *position = definitions[index].range_position;
        *requested = definitions[index].range_requested;
    }
}

static int clipboard_write_all(int descriptor,
                               const uint8_t* data,
                               size_t data_len)
{
    size_t written = 0u;

    while (written < data_len)
    {
        ssize_t result = write(descriptor,
                               data + written,
                               data_len - written);

        if (result < 0 && errno == EINTR)
            continue;
        if (result <= 0)
            return 0;
        written += (size_t)result;
    }
    return 1;
}

static int clipboard_write_sparse_marker(
    int descriptor,
    const clipboard_file_definition* definition)
{
    size_t written = 0u;

    if (ftruncate(descriptor, (off_t)definition->size) != 0)
        return 0;
    while (written < definition->bytes_len)
    {
        ssize_t result = pwrite(
            descriptor,
            definition->bytes + written,
            definition->bytes_len - written,
            (off_t)(definition->bytes_offset + (uint64_t)written));

        if (result < 0 && errno == EINTR)
            continue;
        if (result <= 0)
            return 0;
        written += (size_t)result;
    }
    return 1;
}

static int clipboard_create_client_file(
    const clipboard_file_definition* definition,
    const char* path)
{
    uint8_t chunk[4096];
    uint64_t offset = 0u;
    int descriptor = -1;
    int ok = 1;

    descriptor = open(path,
                      O_CREAT | O_EXCL | O_WRONLY,
                      S_IRUSR | S_IWUSR);
    if (descriptor < 0)
        return 0;
    if (definition->pattern == CLIPBOARD_FILE_SPARSE)
    {
        ok = clipboard_write_sparse_marker(descriptor, definition);
    }
    else
    {
        while (ok && offset < definition->size)
        {
            uint64_t remaining = definition->size - offset;
            uint32_t requested =
                remaining > sizeof(chunk)
                    ? (uint32_t)sizeof(chunk)
                    : (uint32_t)remaining;
            size_t generated = clipboard_file_fill(definition,
                                                   offset,
                                                   requested,
                                                   chunk,
                                                   sizeof(chunk));

            if (generated == SIZE_MAX ||
                generated != (size_t)requested ||
                !clipboard_write_all(descriptor, chunk, generated))
                ok = 0;
            offset += generated != SIZE_MAX ? (uint64_t)generated : 0u;
        }
    }
    if (close(descriptor) != 0)
        ok = 0;
    if (!ok)
        (void)unlink(path);
    return ok;
}

static void clipboard_remove_client_files(
    server_client_clipboard_provider* provider)
{
    unsigned int index = 0u;

    if (!provider)
        return;
    for (index = 0u; index < CLIPBOARD_FILE_COUNT; index++)
    {
        if (provider->client_paths[index][0] != '\0')
        {
            (void)unlink(provider->client_paths[index]);
            provider->client_paths[index][0] = '\0';
        }
    }
    if (provider->client_directory[0] != '\0')
    {
        (void)rmdir(provider->client_directory);
        provider->client_directory[0] = '\0';
    }
}

static int clipboard_prepare_client_files(
    server_client_clipboard_provider* provider)
{
    char directory[] = "/tmp/librdp-clipboard-files-XXXXXX";
    char* created = NULL;
    unsigned int index = 0u;

    if (!provider)
        return 0;
    created = mkdtemp(directory);
    if (!created ||
        snprintf(provider->client_directory,
                 sizeof(provider->client_directory),
                 "%s",
                 created) < 0)
        return 0;
    for (index = 0u; index < CLIPBOARD_FILE_COUNT; index++)
    {
        int length = snprintf(provider->client_paths[index],
                              sizeof(provider->client_paths[index]),
                              "%s/%s",
                              provider->client_directory,
                              clipboard_client_files[index].name);

        if (length < 0 ||
            (size_t)length >= sizeof(provider->client_paths[index]) ||
            !clipboard_create_client_file(
                &clipboard_client_files[index],
                provider->client_paths[index]))
        {
            clipboard_remove_client_files(provider);
            return 0;
        }
        provider->client_file_entries[index].path =
            provider->client_paths[index];
        provider->client_file_entries[index].name =
            clipboard_client_files[index].name;
    }
    return 1;
}

static int clipboard_prepare_server_file_group(
    server_client_clipboard_provider* provider)
{
    librdp_clipboard_file_metadata metadata[CLIPBOARD_FILE_COUNT];
    size_t encoded_len = 0u;
    unsigned int index = 0u;

    if (!provider)
        return 0;
    for (index = 0u; index < CLIPBOARD_FILE_COUNT; index++)
    {
        if (librdp_clipboard_file_metadata_init(&metadata[index]) !=
            LIBRDP_STATUS_OK)
            return 0;
        metadata[index].name = clipboard_server_files[index].name;
        metadata[index].file_size = clipboard_server_files[index].size;
    }
    if (librdp_clipboard_file_group_encode(metadata,
                                           CLIPBOARD_FILE_COUNT,
                                           NULL,
                                           0u,
                                           &encoded_len) !=
        LIBRDP_STATUS_OK)
        return 0;
    provider->server_file_group = (uint8_t*)malloc(encoded_len);
    if (!provider->server_file_group)
        return 0;
    if (librdp_clipboard_file_group_encode(
            metadata,
            CLIPBOARD_FILE_COUNT,
            provider->server_file_group,
            encoded_len,
            &provider->server_file_group_len) !=
        LIBRDP_STATUS_OK)
    {
        free(provider->server_file_group);
        provider->server_file_group = NULL;
        provider->server_file_group_len = 0u;
        return 0;
    }
    return 1;
}

static int clipboard_file_group_matches(
    const uint8_t* data,
    size_t data_len,
    const clipboard_file_definition* definitions)
{
    uint32_t count = 0u;
    unsigned int index = 0u;

    if (!data || !definitions ||
        librdp_clipboard_file_group_count(data,
                                          data_len,
                                          &count) !=
            LIBRDP_STATUS_OK ||
        count != CLIPBOARD_FILE_COUNT)
        return 0;
    for (index = 0u; index < CLIPBOARD_FILE_COUNT; index++)
    {
        librdp_clipboard_file_metadata metadata;
        char name[96];
        size_t name_len = 0u;

        if (librdp_clipboard_file_metadata_init(&metadata) !=
                LIBRDP_STATUS_OK ||
            librdp_clipboard_file_group_get(data,
                                            data_len,
                                            index,
                                            &metadata,
                                            name,
                                            sizeof(name),
                                            &name_len) !=
                LIBRDP_STATUS_OK ||
            name_len != strlen(definitions[index].name) + 1u ||
            strcmp(name, definitions[index].name) != 0 ||
            metadata.file_size != definitions[index].size ||
            metadata.attributes !=
                LIBRDP_CLIPBOARD_FILE_ATTRIBUTE_NORMAL)
            return 0;
    }
    return 1;
}

server_client_clipboard_provider* server_client_clipboard_provider_new(
    const server_client_clipboard_profile* profile)
{
    server_client_clipboard_provider* provider =
        (server_client_clipboard_provider*)calloc(1u, sizeof(*provider));

    if (!provider)
        return NULL;
    provider->profile = profile;
    atomic_init(&provider->offers, 0u);
    atomic_init(&provider->local_requests, 0u);
    atomic_init(&provider->remote_requests, 0u);
    atomic_init(&provider->remote_data, 0u);
    atomic_init(&provider->local_file_requests, 0u);
    atomic_init(&provider->remote_file_requests, 0u);
    atomic_init(&provider->remote_file_responses, 0u);
    atomic_init(&provider->client_format_events, 0u);
    atomic_init(&provider->client_data_events, 0u);
    atomic_init(&provider->client_request_events, 0u);
    atomic_init(&provider->client_file_responses, 0u);
    atomic_init(&provider->failures, 0u);
    if (server_client_clipboard_profile_is_file_transfer(profile) &&
        (!clipboard_prepare_client_files(provider) ||
         !clipboard_prepare_server_file_group(provider)))
    {
        clipboard_remove_client_files(provider);
        free(provider->server_file_group);
        free(provider);
        return NULL;
    }
    return provider;
}

void server_client_clipboard_provider_free(
    server_client_clipboard_provider* provider)
{
    if (!provider)
        return;
    clipboard_remove_client_files(provider);
    free(provider->server_file_group);
    free(provider);
}

static librdp_status clipboard_start(
    void* context,
    const server_platform_clipboard_sink* sink)
{
    server_client_clipboard_provider* provider =
        (server_client_clipboard_provider*)context;
    server_platform_clipboard_format format;

    if (!provider || !sink || !sink->formats || !sink->data ||
        !sink->request || !sink->file_request || !sink->cancel)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    provider->sink = *sink;
    if (provider->profile)
    {
        memset(&format, 0, sizeof(format));
        format.id = provider->profile->format_id;
        format.mime_type = provider->profile->mime_type;
        provider->sink.formats(&format,
                               1u,
                               1u,
                               provider->sink.user_data);
    }
    return LIBRDP_STATUS_OK;
}

static void clipboard_stop(void* context)
{
    server_client_clipboard_provider* provider =
        (server_client_clipboard_provider*)context;

    if (!provider)
        return;
    provider->request_pending = 0;
    provider->file_request_pending = 0;
    memset(&provider->sink, 0, sizeof(provider->sink));
}

/*
 * Defer client-data requests until provider dispatch because the runtime
 * commits the offered ownership generation after this callback returns.
 */
static librdp_status clipboard_publish(
    void* context,
    const server_platform_clipboard_offer* offer)
{
    server_client_clipboard_provider* provider =
        (server_client_clipboard_provider*)context;
    size_t index = 0u;
    int matched = 0;

    if (!provider || !offer ||
        (offer->format_count > 0u && !offer->formats))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    atomic_fetch_add_explicit(&provider->offers, 1u, memory_order_relaxed);
    if (!provider->profile || offer->format_count == 0u)
        return LIBRDP_STATUS_OK;
    if (offer->peer_id == 0u || offer->generation == 0u ||
        offer->ownership_generation == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (index = 0u; index < offer->format_count; index++)
    {
        if (offer->formats[index].id == provider->profile->format_id)
        {
            matched = 1;
            break;
        }
    }
    if (!matched)
    {
        atomic_fetch_add_explicit(&provider->failures,
                                  1u,
                                  memory_order_release);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (atomic_load_explicit(&provider->remote_data,
                             memory_order_acquire) > 0u ||
        provider->request_pending)
        return LIBRDP_STATUS_OK;
    memset(&provider->pending_request, 0, sizeof(provider->pending_request));
    provider->pending_request.peer_id = offer->peer_id;
    provider->pending_request.generation = offer->generation;
    provider->pending_request.ownership_generation =
        offer->ownership_generation;
    provider->pending_request.request_id =
        CLIPBOARD_FILE_DESCRIPTOR_REQUEST_ID;
    provider->pending_request.format_id = provider->profile->format_id;
    provider->request_pending = 1;
    return LIBRDP_STATUS_OK;
}

/*
 * Complete a client request from deterministic provider-owned bytes through
 * the native-provider sink used by the application server.
 */
static librdp_status clipboard_request_data(void* context,
                                            uint64_t request_id,
                                            uint32_t format_id)
{
    server_client_clipboard_provider* provider =
        (server_client_clipboard_provider*)context;
    server_platform_clipboard_data response;

    if (!provider || !provider->profile || request_id == 0u ||
        format_id != provider->profile->format_id ||
        !provider->sink.data)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&response, 0, sizeof(response));
    response.request_id = request_id;
    response.format_id = format_id;
    response.status = LIBRDP_STATUS_OK;
    if (server_client_clipboard_profile_is_file_transfer(
            provider->profile))
    {
        response.data = provider->server_file_group;
        response.data_len = provider->server_file_group_len;
    }
    else
    {
        response.data = provider->profile->server_data;
        response.data_len = provider->profile->server_data_len;
    }
    response.final_chunk = 1;
    atomic_fetch_add_explicit(&provider->local_requests,
                              1u,
                              memory_order_release);
    provider->sink.data(&response, provider->sink.user_data);
    return LIBRDP_STATUS_OK;
}

static librdp_status clipboard_request_file(
    void* context,
    const server_platform_clipboard_file_request* request)
{
    server_client_clipboard_provider* provider =
        (server_client_clipboard_provider*)context;
    server_platform_clipboard_data response;
    uint8_t payload[CLIPBOARD_FILE_RESPONSE_BYTES];
    int32_t file_index = 0;
    uint32_t flags = 0u;
    uint64_t position = 0u;
    uint32_t requested = 0u;
    size_t payload_len = 0u;

    if (!provider || !request || request->request_id == 0u ||
        !provider->sink.data ||
        !server_client_clipboard_profile_is_file_transfer(
            provider->profile) ||
        provider->local_file_task >= CLIPBOARD_FILE_TASK_COUNT)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    clipboard_file_task(clipboard_server_files,
                        provider->local_file_task,
                        &file_index,
                        &flags,
                        &position,
                        &requested);
    if (request->file_index != file_index ||
        request->flags != flags ||
        request->position != position ||
        request->requested_bytes != requested)
    {
        atomic_fetch_add_explicit(&provider->failures,
                                  1u,
                                  memory_order_release);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    if (flags == LIBRDP_CLIPBOARD_FILECONTENTS_SIZE)
    {
        clipboard_write_u64_le(
            payload,
            clipboard_server_files[(unsigned int)file_index].size);
        payload_len = 8u;
    }
    else
    {
        payload_len = clipboard_file_fill(
            &clipboard_server_files[(unsigned int)file_index],
            position,
            requested,
            payload,
            sizeof(payload));
        if (payload_len == SIZE_MAX)
            return LIBRDP_STATUS_LIMIT_EXCEEDED;
    }
    memset(&response, 0, sizeof(response));
    response.peer_id = request->peer_id;
    response.generation = request->generation;
    response.ownership_generation = request->ownership_generation;
    response.request_id = request->request_id;
    response.stream_id = request->stream_id;
    response.status = LIBRDP_STATUS_OK;
    response.data = payload;
    response.data_len = payload_len;
    response.final_chunk = 1;
    provider->sink.data(&response, provider->sink.user_data);
    provider->local_file_task++;
    atomic_fetch_add_explicit(&provider->local_file_requests,
                              1u,
                              memory_order_release);
    return LIBRDP_STATUS_OK;
}

static librdp_status clipboard_write(
    void* context,
    const server_platform_clipboard_data* data)
{
    server_client_clipboard_provider* provider =
        (server_client_clipboard_provider*)context;

    if (!provider || !data ||
        (data->data_len > 0u && !data->data))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!provider->profile)
        return LIBRDP_STATUS_OK;
    if (server_client_clipboard_profile_is_file_transfer(
            provider->profile))
    {
        if (data->status != LIBRDP_STATUS_OK || !data->final_chunk)
        {
            atomic_fetch_add_explicit(&provider->failures,
                                      1u,
                                      memory_order_release);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        if (data->request_id ==
                CLIPBOARD_FILE_DESCRIPTOR_REQUEST_ID &&
            data->format_id ==
                LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW)
        {
            if (atomic_load_explicit(&provider->remote_data,
                                     memory_order_acquire) != 0u ||
                !clipboard_file_group_matches(
                    data->data,
                    data->data_len,
                    clipboard_client_files))
            {
                atomic_fetch_add_explicit(&provider->failures,
                                          1u,
                                          memory_order_release);
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            }
            atomic_fetch_add_explicit(&provider->remote_data,
                                      1u,
                                      memory_order_release);
            provider->file_request_pending = 1;
            return LIBRDP_STATUS_OK;
        }
        if (provider->remote_file_task >=
                CLIPBOARD_FILE_TASK_COUNT ||
            data->request_id !=
                CLIPBOARD_FILE_REQUEST_ID_BASE +
                    provider->remote_file_task ||
            data->stream_id !=
                CLIPBOARD_FILE_STREAM_ID_BASE +
                    provider->remote_file_task)
        {
            atomic_fetch_add_explicit(&provider->failures,
                                      1u,
                                      memory_order_release);
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        {
            int32_t file_index = 0;
            uint32_t flags = 0u;
            uint64_t position = 0u;
            uint32_t requested = 0u;

            clipboard_file_task(clipboard_client_files,
                                provider->remote_file_task,
                                &file_index,
                                &flags,
                                &position,
                                &requested);
            if (!clipboard_file_response_matches(
                    &clipboard_client_files[
                        (unsigned int)file_index],
                    flags,
                    position,
                    requested,
                    data->data,
                    data->data_len))
            {
                atomic_fetch_add_explicit(&provider->failures,
                                          1u,
                                          memory_order_release);
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            }
        }
        provider->remote_file_task++;
        atomic_fetch_add_explicit(&provider->remote_file_responses,
                                  1u,
                                  memory_order_release);
        if (provider->remote_file_task <
            CLIPBOARD_FILE_TASK_COUNT)
            provider->file_request_pending = 1;
        return LIBRDP_STATUS_OK;
    }
    if (data->status != LIBRDP_STATUS_OK || !data->final_chunk ||
        data->request_id != CLIPBOARD_FILE_DESCRIPTOR_REQUEST_ID ||
        data->format_id != provider->profile->format_id ||
        !clipboard_payload_matches(
            data->data,
            data->data_len,
            provider->profile->client_data,
            provider->profile->client_data_len,
            provider->profile->client_decoded_sha256))
    {
        atomic_fetch_add_explicit(&provider->failures,
                                  1u,
                                  memory_order_release);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    atomic_fetch_add_explicit(&provider->remote_data,
                              1u,
                              memory_order_release);
    return LIBRDP_STATUS_OK;
}

static void clipboard_cancel(void* context,
                             uint32_t peer_id,
                             uint32_t generation)
{
    (void)context;
    (void)peer_id;
    (void)generation;
}

static void clipboard_release(void* context, uint64_t generation)
{
    (void)context;
    (void)generation;
}

static librdp_status clipboard_get_pollfds(void* context,
                                           struct pollfd* fds,
                                           size_t capacity,
                                           size_t* count)
{
    if (!context || !count || (capacity > 0u && !fds))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *count = 0u;
    return LIBRDP_STATUS_OK;
}

static librdp_status clipboard_notify_poll(
    void* context,
    const struct pollfd* fds,
    size_t count)
{
    (void)fds;
    return context && count == 0u
               ? LIBRDP_STATUS_OK
               : LIBRDP_STATUS_INVALID_ARGUMENT;
}

/*
 * Run deferred requests on the serialized server-host thread and clear state
 * first so a synchronous completion cannot schedule a duplicate request.
 */
static librdp_status clipboard_dispatch(void* context,
                                        unsigned int max_events)
{
    server_client_clipboard_provider* provider =
        (server_client_clipboard_provider*)context;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!provider || max_events == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (provider->request_pending)
    {
        provider->request_pending = 0;
        status = provider->sink.request(&provider->pending_request,
                                        provider->sink.user_data);
        if (status != LIBRDP_STATUS_OK)
        {
            atomic_fetch_add_explicit(&provider->failures,
                                      1u,
                                      memory_order_release);
            return status;
        }
        atomic_fetch_add_explicit(&provider->remote_requests,
                                  1u,
                                  memory_order_release);
        return LIBRDP_STATUS_OK;
    }
    if (!provider->file_request_pending)
        return LIBRDP_STATUS_OK;
    provider->file_request_pending = 0;
    memset(&provider->pending_file_request,
           0,
           sizeof(provider->pending_file_request));
    provider->pending_file_request.peer_id =
        provider->pending_request.peer_id;
    provider->pending_file_request.generation =
        provider->pending_request.generation;
    provider->pending_file_request.ownership_generation =
        provider->pending_request.ownership_generation;
    provider->pending_file_request.request_id =
        CLIPBOARD_FILE_REQUEST_ID_BASE +
        provider->remote_file_task;
    provider->pending_file_request.stream_id =
        CLIPBOARD_FILE_STREAM_ID_BASE +
        provider->remote_file_task;
    clipboard_file_task(
        clipboard_client_files,
        provider->remote_file_task,
        &provider->pending_file_request.file_index,
        &provider->pending_file_request.flags,
        &provider->pending_file_request.position,
        &provider->pending_file_request.requested_bytes);
    status = provider->sink.file_request(
        &provider->pending_file_request,
        provider->sink.user_data);
    if (status != LIBRDP_STATUS_OK)
    {
        atomic_fetch_add_explicit(&provider->failures,
                                  1u,
                                  memory_order_release);
        return status;
    }
    atomic_fetch_add_explicit(&provider->remote_file_requests,
                              1u,
                              memory_order_release);
    return LIBRDP_STATUS_OK;
}

static librdp_status clipboard_get_timeout(void* context,
                                           int* timeout_ms)
{
    server_client_clipboard_provider* provider =
        (server_client_clipboard_provider*)context;

    if (!provider || !timeout_ms)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *timeout_ms =
        provider->request_pending ||
                provider->file_request_pending
            ? 0
            : -1;
    return LIBRDP_STATUS_OK;
}

static const server_platform_event_source_vtable clipboard_events = {
    SERVER_PLATFORM_EVENT_SOURCE_VERSION,
    sizeof(server_platform_event_source_vtable),
    clipboard_get_pollfds,
    clipboard_notify_poll,
    clipboard_dispatch,
    clipboard_get_timeout,
};

static const server_platform_clipboard_vtable clipboard_vtable = {
    SERVER_PLATFORM_CLIPBOARD_VERSION,
    sizeof(server_platform_clipboard_vtable),
    clipboard_start,
    clipboard_stop,
    clipboard_publish,
    clipboard_request_data,
    clipboard_request_file,
    clipboard_write,
    clipboard_cancel,
    clipboard_release,
    &clipboard_events,
};

const server_platform_clipboard_vtable*
server_client_clipboard_provider_vtable(void)
{
    return &clipboard_vtable;
}

int server_client_clipboard_provider_has_offer(
    const server_client_clipboard_provider* provider)
{
    return provider &&
           atomic_load_explicit(&provider->offers,
                                memory_order_acquire) > 0u;
}

librdp_status server_client_clipboard_provider_publish_client(
    server_client_clipboard_provider* provider,
    librdp_session* session)
{
    if (!provider || !session || !provider->profile)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (server_client_clipboard_profile_is_file_transfer(
            provider->profile))
    {
        return librdp_session_clipboard_set_files(
            session,
            provider->client_file_entries,
            CLIPBOARD_FILE_COUNT);
    }
    if (provider->profile->format_name)
    {
        return librdp_session_clipboard_set_named_data(
            session,
            provider->profile->format_id,
            provider->profile->format_name,
            provider->profile->client_data,
            provider->profile->client_data_len);
    }
    return librdp_session_clipboard_set_data(
        session,
        provider->profile->format_id,
        provider->profile->client_data,
        provider->profile->client_data_len);
}

static librdp_status clipboard_client_request_task(
    server_client_clipboard_provider* provider,
    librdp_session* session)
{
    int32_t file_index = 0;
    uint32_t flags = 0u;
    uint64_t position = 0u;
    uint32_t requested = 0u;
    uint32_t stream_id = 0u;

    if (!provider || !session ||
        provider->client_file_task >= CLIPBOARD_FILE_TASK_COUNT)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    clipboard_file_task(clipboard_server_files,
                        provider->client_file_task,
                        &file_index,
                        &flags,
                        &position,
                        &requested);
    stream_id =
        CLIPBOARD_CLIENT_STREAM_ID_BASE +
        provider->client_file_task;
    if (flags == LIBRDP_CLIPBOARD_FILECONTENTS_SIZE)
    {
        return librdp_session_clipboard_request_file_size(
            session,
            stream_id,
            file_index);
    }
    return librdp_session_clipboard_request_file_range(
        session,
        stream_id,
        file_index,
        position,
        requested);
}

static int clipboard_client_handle_formats(
    server_client_clipboard_provider* provider,
    librdp_session* session,
    const librdp_clipboard_formats_event* formats)
{
    uint32_t index = 0u;
    int matched = 0;

    atomic_fetch_add_explicit(&provider->client_format_events,
                              1u,
                              memory_order_release);
    for (index = 0u; index < formats->count; index++)
    {
        if (formats->formats[index].format_id ==
            LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW)
        {
            matched = 1;
            break;
        }
    }
    if (!matched)
    {
        atomic_fetch_add_explicit(&provider->failures,
                                  1u,
                                  memory_order_release);
    }
    else if (!provider->client_data_requested)
    {
        if (librdp_session_clipboard_request_data(
                session,
                LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW) !=
            LIBRDP_STATUS_OK)
        {
            atomic_fetch_add_explicit(&provider->failures,
                                      1u,
                                      memory_order_release);
        }
        else
        {
            provider->client_data_requested = 1;
        }
    }
    return 1;
}

static int clipboard_client_handle_data(
    server_client_clipboard_provider* provider,
    librdp_session* session,
    const librdp_clipboard_data_event* data)
{
    if (!data->ok ||
        data->format_id !=
            LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW ||
        atomic_load_explicit(&provider->client_data_events,
                             memory_order_acquire) != 0u ||
        !clipboard_file_group_matches(data->data,
                                      data->data_len,
                                      clipboard_server_files))
    {
        atomic_fetch_add_explicit(&provider->failures,
                                  1u,
                                  memory_order_release);
        return 1;
    }
    atomic_fetch_add_explicit(&provider->client_data_events,
                              1u,
                              memory_order_release);
    if (clipboard_client_request_task(provider, session) !=
        LIBRDP_STATUS_OK)
    {
        atomic_fetch_add_explicit(&provider->failures,
                                  1u,
                                  memory_order_release);
    }
    return 1;
}

static int clipboard_client_handle_file_contents(
    server_client_clipboard_provider* provider,
    librdp_session* session,
    const librdp_clipboard_file_contents_event* contents)
{
    int32_t file_index = 0;
    uint32_t flags = 0u;
    uint64_t position = 0u;
    uint32_t requested = 0u;

    if (provider->client_file_task >=
        CLIPBOARD_FILE_TASK_COUNT)
    {
        atomic_fetch_add_explicit(&provider->failures,
                                  1u,
                                  memory_order_release);
        return 1;
    }
    clipboard_file_task(clipboard_server_files,
                        provider->client_file_task,
                        &file_index,
                        &flags,
                        &position,
                        &requested);
    if (!contents->ok ||
        contents->stream_id !=
            CLIPBOARD_CLIENT_STREAM_ID_BASE +
                provider->client_file_task ||
        contents->file_index != file_index ||
        contents->flags != flags ||
        contents->position != position ||
        contents->requested != requested ||
        !clipboard_file_response_matches(
            &clipboard_server_files[(unsigned int)file_index],
            flags,
            position,
            requested,
            contents->data,
            contents->data_len))
    {
        atomic_fetch_add_explicit(&provider->failures,
                                  1u,
                                  memory_order_release);
        return 1;
    }
    provider->client_file_task++;
    atomic_fetch_add_explicit(&provider->client_file_responses,
                              1u,
                              memory_order_release);
    if (provider->client_file_task <
            CLIPBOARD_FILE_TASK_COUNT &&
        clipboard_client_request_task(provider, session) !=
            LIBRDP_STATUS_OK)
    {
        atomic_fetch_add_explicit(&provider->failures,
                                  1u,
                                  memory_order_release);
    }
    return 1;
}

int server_client_clipboard_provider_handle_client_event(
    server_client_clipboard_provider* provider,
    librdp_session* session,
    const librdp_event* event)
{
    if (!provider || !session || !event ||
        !server_client_clipboard_profile_is_file_transfer(
            provider->profile))
        return 0;
    switch (event->type)
    {
        case LIBRDP_EVENT_CLIPBOARD_FORMATS:
            return clipboard_client_handle_formats(
                provider,
                session,
                &event->data.clipboard_formats);
        case LIBRDP_EVENT_CLIPBOARD_DATA:
            return clipboard_client_handle_data(
                provider,
                session,
                &event->data.clipboard_data);
        case LIBRDP_EVENT_CLIPBOARD_REQUEST:
            if (event->data.clipboard_request.format_id !=
                LIBRDP_CLIPBOARD_FORMAT_FILEGROUPDESCRIPTORW)
            {
                atomic_fetch_add_explicit(&provider->failures,
                                          1u,
                                          memory_order_release);
            }
            atomic_fetch_add_explicit(
                &provider->client_request_events,
                1u,
                memory_order_release);
            return 1;
        case LIBRDP_EVENT_CLIPBOARD_FILE_CONTENTS:
            return clipboard_client_handle_file_contents(
                provider,
                session,
                &event->data.clipboard_file_contents);
        default:
            return 0;
    }
}

int server_client_clipboard_provider_complete(
    const server_client_clipboard_provider* provider)
{
    if (!provider || !provider->profile)
        return 0;
    if (server_client_clipboard_profile_is_file_transfer(
            provider->profile))
    {
        return atomic_load_explicit(&provider->local_requests,
                                    memory_order_acquire) == 1u &&
               atomic_load_explicit(&provider->remote_requests,
                                    memory_order_acquire) == 1u &&
               atomic_load_explicit(&provider->remote_data,
                                    memory_order_acquire) == 1u &&
               atomic_load_explicit(&provider->local_file_requests,
                                    memory_order_acquire) ==
                   CLIPBOARD_FILE_TASK_COUNT &&
               atomic_load_explicit(&provider->remote_file_requests,
                                    memory_order_acquire) ==
                   CLIPBOARD_FILE_TASK_COUNT &&
               atomic_load_explicit(&provider->remote_file_responses,
                                    memory_order_acquire) ==
                   CLIPBOARD_FILE_TASK_COUNT &&
               atomic_load_explicit(&provider->client_format_events,
                                    memory_order_acquire) > 0u &&
               atomic_load_explicit(&provider->client_data_events,
                                    memory_order_acquire) == 1u &&
               atomic_load_explicit(&provider->client_request_events,
                                    memory_order_acquire) == 1u &&
               atomic_load_explicit(&provider->client_file_responses,
                                    memory_order_acquire) ==
                   CLIPBOARD_FILE_TASK_COUNT &&
               atomic_load_explicit(&provider->failures,
                                    memory_order_acquire) == 0u;
    }
    return atomic_load_explicit(&provider->local_requests,
                                memory_order_acquire) == 1u &&
           atomic_load_explicit(&provider->remote_requests,
                                memory_order_acquire) == 1u &&
           atomic_load_explicit(&provider->remote_data,
                                memory_order_acquire) == 1u &&
           atomic_load_explicit(&provider->failures,
                                memory_order_acquire) == 0u;
}
