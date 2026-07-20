/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: atomic state exchange for cooperating integration-test processes.
 * Coverage: complete publication and strict parsing of bounded port/stage
 * records shared by independently scheduled smoke processes.
 * Bug classes: partial reads, stale temporary files, numeric overflow, short
 * writes, interrupted writes, and descriptor cleanup failures.
 * Determinism: writers atomically rename complete records and readers accept
 * one fixed text grammar.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "test_process_state.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int test_process_state_write_all(int fd,
                                        const char* data,
                                        size_t length)
{
    size_t offset = 0u;

    while (offset < length)
    {
        ssize_t written = write(fd, data + offset, length - offset);

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return 0;
        offset += (size_t)written;
    }
    return 1;
}

int test_process_state_write(const char* path,
                             uint16_t port,
                             uint32_t stage)
{
    char contents[96];
    char* temporary = NULL;
    size_t temporary_capacity = 0u;
    int contents_length = 0;
    int temporary_length = 0;
    int fd = -1;
    int result = 0;

    if (!path || path[0] == '\0' || port == 0u)
        return 0;
    if (strlen(path) > SIZE_MAX - 48u)
        return 0;
    temporary_capacity = strlen(path) + 48u;
    temporary = (char*)malloc(temporary_capacity);
    if (!temporary)
        return 0;
    temporary_length = snprintf(temporary,
                                temporary_capacity,
                                "%s.tmp.%ld",
                                path,
                                (long)getpid());
    contents_length = snprintf(contents,
                               sizeof(contents),
                               "port=%u\nstage=%lu\n",
                               (unsigned int)port,
                               (unsigned long)stage);
    if (temporary_length <= 0 ||
        (size_t)temporary_length >= temporary_capacity ||
        contents_length <= 0 ||
        (size_t)contents_length >= sizeof(contents))
    {
        free(temporary);
        return 0;
    }
    fd = open(temporary,
              O_WRONLY | O_CREAT | O_TRUNC,
              S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        free(temporary);
        return 0;
    }
    result = test_process_state_write_all(
        fd,
        contents,
        (size_t)contents_length);
    if (close(fd) != 0)
        result = 0;
    if (result && rename(temporary, path) != 0)
        result = 0;
    if (!result)
        (void)unlink(temporary);
    free(temporary);
    return result;
}

int test_process_state_read(const char* path,
                            uint16_t* port,
                            uint32_t* stage)
{
    FILE* file = NULL;
    unsigned long parsed_port = 0u;
    unsigned long parsed_stage = 0u;
    int fields = 0;

    if (!path || !port || !stage)
        return 0;
    file = fopen(path, "rb");
    if (!file)
        return 0;
    fields = fscanf(file,
                    "port=%lu\nstage=%lu\n",
                    &parsed_port,
                    &parsed_stage);
    if (fclose(file) != 0)
        return 0;
    if (fields != 2 || parsed_port == 0u ||
        parsed_port > UINT16_MAX ||
        parsed_stage > UINT32_MAX)
        return 0;
    *port = (uint16_t)parsed_port;
    *stage = (uint32_t)parsed_stage;
    return 1;
}
