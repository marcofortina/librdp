/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: fuzz target for standalone fuzz harness main used when libFuzzer is
 * not linked by the compiler.
 * Coverage: feeds arbitrary bytes through parser, decoder, and writer paths
 * selected by this target.
 * Bug classes: malformed PDU bounds, integer overflows, state-independent
 * decoder edge cases, and cleanup lifetime.
 * Determinism: no network, clock, filesystem mutation, or host backend
 * dependency is used by the fuzz entrypoint.
 */


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

static int fuzz_main_run_stream(FILE* input)
{
    uint8_t* data = NULL;
    size_t length = 0;
    size_t capacity = 0;
    int c = 0;

    while ((c = fgetc(input)) != EOF)
    {
        if (length == capacity)
        {
            size_t next = capacity ? capacity * 2u : 4096u;
            uint8_t* resized = (uint8_t*)realloc(data, next);
            if (!resized)
            {
                free(data);
                return 1;
            }
            data = resized;
            capacity = next;
        }
        data[length++] = (uint8_t)c;
    }

    (void)LLVMFuzzerTestOneInput(data, length);
    free(data);
    return 0;
}

int main(int argc, char** argv)
{
    int i = 0;

    if (argc <= 1)
        return fuzz_main_run_stream(stdin);

    for (i = 1; i < argc; i++)
    {
        FILE* input = fopen(argv[i], "rb");
        int status = 0;

        if (!input)
            return 1;
        status = fuzz_main_run_stream(input);
        fclose(input);
        if (status != 0)
            return status;
    }
    return 0;
}
