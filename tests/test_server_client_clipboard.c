/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic clipboard provider for client/server loopback smoke.
 * Coverage: bidirectional Unicode text, registered HTML, and PNG payloads
 * across the public client API and application server host.
 * Bug classes: ownership races, request-correlation loss, payload corruption,
 * duplicate requests, and provider dispatch outside the server owner thread.
 * Determinism: payloads and request IDs are fixed and transport is loopback.
 */

#include "test_server_client_clipboard.h"

#include "graphics/gdi_image.h"

#include <librdp/clipboard.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define CLIPBOARD_SHA256_BYTES 32u

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
};

struct server_client_clipboard_provider
{
    server_platform_clipboard_sink sink;
    server_platform_clipboard_request pending_request;
    const server_client_clipboard_profile* profile;
    atomic_uint offers;
    atomic_uint local_requests;
    atomic_uint remote_requests;
    atomic_uint remote_data;
    atomic_uint failures;
    int request_pending;
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
    atomic_init(&provider->failures, 0u);
    return provider;
}

void server_client_clipboard_provider_free(
    server_client_clipboard_provider* provider)
{
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
    provider->pending_request.request_id = 1009u;
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
    response.data = provider->profile->server_data;
    response.data_len = provider->profile->server_data_len;
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
    return context && request && request->request_id != 0u
               ? LIBRDP_STATUS_OK
               : LIBRDP_STATUS_INVALID_ARGUMENT;
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
    if (data->status != LIBRDP_STATUS_OK || !data->final_chunk ||
        data->request_id != 1009u ||
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
    if (!provider->request_pending)
        return LIBRDP_STATUS_OK;
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

static librdp_status clipboard_get_timeout(void* context,
                                           int* timeout_ms)
{
    server_client_clipboard_provider* provider =
        (server_client_clipboard_provider*)context;

    if (!provider || !timeout_ms)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *timeout_ms = provider->request_pending ? 0 : -1;
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

int server_client_clipboard_provider_complete(
    const server_client_clipboard_provider* provider)
{
    if (!provider || !provider->profile)
        return 0;
    return atomic_load_explicit(&provider->local_requests,
                                memory_order_acquire) == 1u &&
           atomic_load_explicit(&provider->remote_requests,
                                memory_order_acquire) == 1u &&
           atomic_load_explicit(&provider->remote_data,
                                memory_order_acquire) == 1u &&
           atomic_load_explicit(&provider->failures,
                                memory_order_acquire) == 0u;
}
