#include "common/charset.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    rdp_buffer buffer;
    uint8_t* utf16 = NULL;
    char* utf8 = NULL;
    char* text = NULL;
    size_t utf16_len = 0;
    size_t utf8_len = 0;
    size_t bounded = size < 4096u ? size : 4096u;

    rdp_buffer_init(&buffer);
    (void)rdp_charset_utf8_bytes_to_utf16le_alloc(data, bounded, 0, &utf16, &utf16_len);
    if (utf16)
        (void)rdp_charset_utf16le_to_utf8_alloc(utf16, utf16_len, 0, &utf8, &utf8_len);
    free(utf8);
    free(utf16);

    if (bounded > 0)
    {
        text = (char*)malloc(bounded + 1u);
        if (text)
        {
            memcpy(text, data, bounded);
            text[bounded] = '\0';
            (void)rdp_charset_utf8_to_utf16le_buffer(text, 1, &buffer);
            free(text);
        }
    }
    rdp_buffer_free(&buffer);
    return 0;
}
