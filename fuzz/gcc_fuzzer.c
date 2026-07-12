/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for GCC conference data parser and writer paths.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include "common/stream.h"
#include "protocol/gcc.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Writer regression path: serializes a bounded client-name case through the
 * GCC client data writer without exposing fuzz-owned memory past the call.
 * Purpose: keep NULL, empty, short, exact-fit, and overlong machine names under
 * sanitizer coverage.
 */
static void fuzz_gcc_write_client_name(const char* client_name)
{
    rdp_buffer buffer;
    rdp_gcc_client_config config;

    memset(&config, 0, sizeof(config));
    config.desktop_width = 1024;
    config.desktop_height = 768;
    config.client_name = client_name;

    rdp_buffer_init(&buffer);
    (void)rdp_gcc_write_client_data_blocks(&buffer, &config);
    rdp_buffer_free(&buffer);
}

/*
 * Token dispatcher: interprets newline-, NUL-, or CR-separated fuzz bytes as
 * client-name cases. Invariant: each token is copied into a local NUL
 * terminated buffer before the writer sees it, and the literal NULL selects
 * the writer's NULL-pointer path.
 */
static void fuzz_gcc_write_input_client_names(const uint8_t* data, size_t size)
{
    size_t offset = 0;
    size_t cases = 0;

    if (!data || size == 0)
    {
        fuzz_gcc_write_client_name(NULL);
        return;
    }

    while (offset <= size && cases < 16u)
    {
        char name[96];
        const char* client_name = name;
        size_t end = offset;
        size_t token_len = 0;
        size_t copy_len = 0;

        while (end < size && data[end] != '\n' && data[end] != '\r' && data[end] != '\0')
            end++;
        token_len = end - offset;
        if (token_len == 4u && memcmp(data + offset, "NULL", 4u) == 0)
        {
            client_name = NULL;
        }
        else
        {
            copy_len = token_len < sizeof(name) - 1u ? token_len : sizeof(name) - 1u;
            if (copy_len > 0)
                memcpy(name, data + offset, copy_len);
            name[copy_len] = '\0';
        }
        fuzz_gcc_write_client_name(client_name);
        cases++;
        if (end >= size)
            break;
        offset = end + 1u;
    }
}

/*
 * Fuzz target: exercises GCC conference data parser and writer paths with one
 * arbitrary input buffer.
 * Bug classes: truncated payloads, inconsistent length fields, count
 * overflows, decoder edge cases, and ownership cleanup.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_stream stream;
    rdp_gcc_user_data_block block;
    rdp_gcc_client_data_summary summary;
    rdp_gcc_conference_response response;
    rdp_gcc_server_data server_data;

    (void)rdp_gcc_parse_client_data_blocks(data, size, &summary);
    (void)rdp_gcc_parse_conference_create_response(data, size, &response);
    (void)rdp_gcc_parse_server_data_blocks(data, size, &server_data);
    fuzz_gcc_write_input_client_names(data, size);
    rdp_stream_init(&stream, data, size);
    while (rdp_stream_remaining(&stream) > 0)
    {
        if (rdp_gcc_read_user_data_block(&stream, &block) != LIBRDP_STATUS_OK)
            break;
    }
    return 0;
}
