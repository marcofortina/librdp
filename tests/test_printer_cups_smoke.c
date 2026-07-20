/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: opt-in CUPS printer backend smoke test.
 * Coverage: destination discovery, XPS format selection, asynchronous submit,
 * completion delivery, spool ownership and captured output integrity.
 * Bug classes: blocked worker, wrong destination, format conversion, truncated
 * output, retained spool content and cleanup failure.
 * Determinism: the caller supplies an isolated CUPS queue and capture path.
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "client/printer_backend.h"
#include "test_xps_package.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CUPS_SMOKE_WAIT_LIMIT 500u
#define CUPS_SMOKE_WAIT_NS 10000000L

static int cups_smoke_write_all(int fd,
                                const uint8_t* data,
                                size_t length)
{
    size_t offset = 0u;

    if (fd < 0 || (!data && length > 0u))
        return 0;
    while (offset < length)
    {
        ssize_t count = write(fd, data + offset, length - offset);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return 0;
        offset += (size_t)count;
    }
    return 1;
}

static int cups_smoke_capture_matches(const char* path)
{
    uint8_t bytes[sizeof(test_xps_package)];
    char extra = 0;
    size_t offset = 0u;
    int fd = -1;
    int match = 0;

    if (!path)
        return 0;
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return 0;
    while (offset < sizeof(bytes))
    {
        ssize_t count = read(fd,
                             bytes + offset,
                             sizeof(bytes) - offset);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            break;
        offset += (size_t)count;
    }
    match = offset == sizeof(bytes) &&
            memcmp(bytes, test_xps_package, sizeof(bytes)) == 0 &&
            read(fd, &extra, sizeof(extra)) == 0;
    (void)close(fd);
    return match;
}

int main(void)
{
    const struct timespec delay = {0, CUPS_SMOKE_WAIT_NS};
    const char* output = getenv("LIBRDP_TEST_CUPS_OUTPUT");
    const char* capture = getenv("LIBRDP_TEST_CUPS_CAPTURE");
    char spool[] = "/tmp/librdp-cups-spool-XXXXXX";
    rdp_printer_backend backend;
    rdp_printer_backend_completion completion;
    uint32_t status = 0u;
    int completed = 0;
    int fd = -1;
    int result = 1;

    memset(&backend, 0, sizeof(backend));
    memset(&completion, 0, sizeof(completion));
    if (!output || !capture)
        return 77;
    (void)unlink(capture);
    fd = mkstemp(spool);
    if (fd < 0)
        return 1;
    if (!cups_smoke_write_all(fd,
                              test_xps_package,
                              sizeof(test_xps_package)) ||
        fsync(fd) != 0)
    {
        (void)close(fd);
        (void)unlink(spool);
        return 1;
    }
    if (close(fd) != 0)
    {
        (void)unlink(spool);
        return 1;
    }
    fd = -1;

    rdp_printer_backend_init_cups(&backend);
    status = rdp_printer_backend_submit_async(&backend,
                                              0u,
                                              output,
                                              "librdp CUPS smoke",
                                              spool,
                                              1);
    if (status != 0u)
        goto cleanup;
    for (unsigned int attempt = 0u;
         attempt < CUPS_SMOKE_WAIT_LIMIT && !completed;
         attempt++)
    {
        completed = rdp_printer_backend_take_completion(
            &backend,
            &completion);
        if (!completed)
            (void)nanosleep(&delay, NULL);
    }
    if (!completed ||
        completion.printer_index != 0u ||
        completion.status != 0u ||
        access(spool, F_OK) == 0 ||
        errno != ENOENT)
        goto cleanup;
    for (unsigned int attempt = 0u;
         attempt < CUPS_SMOKE_WAIT_LIMIT;
         attempt++)
    {
        if (cups_smoke_capture_matches(capture))
        {
            result = 0;
            break;
        }
        (void)nanosleep(&delay, NULL);
    }

cleanup:
    rdp_printer_backend_clear(&backend);
    (void)unlink(spool);
    (void)unlink(capture);
    if (result != 0)
    {
        fprintf(stderr,
                "CUPS smoke failed submit_status=%u completed=%d completion_status=%u\n",
                status,
                completed,
                completion.status);
    }
    return result;
}
