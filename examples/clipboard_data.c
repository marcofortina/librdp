/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdint.h>
#include <stdio.h>

#include <librdp/librdp.h>

int main(void)
{
    static const uint8_t text[] = {
        'c', 0, 'l', 0, 'i', 0, 'p', 0, 'b', 0, 'o', 0, 'a', 0, 'r', 0, 'd', 0,
        ' ', 0, 't', 0, 'e', 0, 'x', 0, 't', 0, 0, 0
    };
    static const uint8_t html[] =
        "Version:0.9\r\n"
        "StartHTML:00000097\r\n"
        "EndHTML:00000132\r\n"
        "StartFragment:00000109\r\n"
        "EndFragment:00000120\r\n"
        "<html><body><!--StartFragment-->hello<!--EndFragment--></body></html>";
    librdp_settings* settings = librdp_settings_new();
    librdp_session* session = NULL;
    librdp_status text_status;
    librdp_status html_status;
    librdp_status clear_status;

    if (!settings)
        return 1;

    session = librdp_session_new(settings);
    librdp_settings_free(settings);
    if (!session)
        return 1;

    text_status = librdp_session_clipboard_set_data(session,
                                                    LIBRDP_CLIPBOARD_FORMAT_UNICODETEXT,
                                                    text,
                                                    sizeof(text) - 1u);
    html_status = librdp_session_clipboard_set_named_data(session,
                                                          LIBRDP_CLIPBOARD_FORMAT_HTML,
                                                          LIBRDP_CLIPBOARD_FORMAT_NAME_HTML,
                                                          html,
                                                          sizeof(html) - 1u);
    clear_status = librdp_session_clipboard_clear(session);

    printf("text=%s html=%s clear=%s\n",
           librdp_status_string(text_status),
           librdp_status_string(html_status),
           librdp_status_string(clear_status));

    librdp_session_free(session);
    return text_status == LIBRDP_STATUS_OK &&
                   html_status == LIBRDP_STATUS_OK &&
                   clear_status == LIBRDP_STATUS_OK ?
               0 :
               1;
}
