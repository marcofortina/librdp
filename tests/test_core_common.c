/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: common runtime tests.
 * Coverage: trace, buffers, charset, and pointer decoding.
 * Bug classes: malformed input, invalid state, bounds, ownership, and cleanup.
 * Determinism: fixtures use synthetic data and local transports only.
 */

#include "test_core_support.h"
#include "test_core_suites.h"

static void trace_default_event(void)
{
    rdp_trace_reset_for_tests();
    rdp_trace_event(RDP_TRACE_CLIENT, "client.test", "value=1");
}

static void trace_enabled_event(void)
{
    setenv("LIBRDP_TRACE_CLIENT", "yes", 1);
    rdp_trace_reset_for_tests();
    rdp_trace_event(RDP_TRACE_CLIENT, "client.test", "value=1");
    unsetenv("LIBRDP_TRACE_CLIENT");
}

static void trace_protocol_hexdump(void)
{
    const uint8_t bytes[] = {0x41, 0x42, 0x00, 0x43};
    setenv("LIBRDP_TRACE_PROTOCOL", "ON", 1);
    setenv("LIBRDP_TRACE_LEVEL", "trace", 1);
    setenv("LIBRDP_TRACE_HEX_BYTES", "2", 1);
    rdp_trace_reset_for_tests();
    rdp_trace_hexdump("rdp.fastpath.pdu", RDP_TRACE_SENSITIVITY_HEADER, bytes, sizeof(bytes));
    unsetenv("LIBRDP_TRACE_PROTOCOL");
    unsetenv("LIBRDP_TRACE_LEVEL");
    unsetenv("LIBRDP_TRACE_HEX_BYTES");
}

static void trace_sensitive_hexdumps(void)
{
    const uint8_t x224_request[] =
        "TPKT-X224-Cookie: mstshash=LIBRDP_IDENTITY_CANARY";
    const uint8_t password[] = "HDR:LIBRDP_PASSWORD_CANARY";
    const uint8_t token[] = "HDR:LIBRDP_CREDSSP_TOKEN_CANARY";
    const uint8_t clipboard[] = "HDR:LIBRDP_CLIPBOARD_CANARY";
    const uint8_t input[] = "HDR:LIBRDP_INPUT_CANARY";
    const uint8_t apdu[] = "HDR:LIBRDP_APDU_CANARY";
    const uint8_t usb[] = "HDR:LIBRDP_USB_CANARY";
    const uint8_t audio[] = "HDR:LIBRDP_AUDIO_CANARY";
    const uint8_t media[] = "HDR:LIBRDP_MEDIA_CANARY";

    setenv("LIBRDP_TRACE_PROTOCOL", "1", 1);
    setenv("LIBRDP_TRACE_LEVEL", "trace", 1);
    setenv("LIBRDP_TRACE_HEX_BYTES", "96", 1);
    unsetenv("LIBRDP_TRACE_UNSAFE");
    rdp_trace_reset_for_tests();
    rdp_trace_hexdump("x224.negotiation.request",
                      RDP_TRACE_SENSITIVITY_AUTH,
                      x224_request,
                      sizeof(x224_request) - 1u);
    rdp_trace_hexdump("rdp.client_info.pdu", RDP_TRACE_SENSITIVITY_AUTH, password, sizeof(password) - 1u);
    rdp_trace_hexdump("credssp.token", RDP_TRACE_SENSITIVITY_AUTH, token, sizeof(token) - 1u);
    rdp_trace_hexdump("client.clipboard.pdu",
                      RDP_TRACE_SENSITIVITY_CLIPBOARD,
                      clipboard,
                      sizeof(clipboard) - 1u);
    rdp_trace_hexdump("client.input.send", RDP_TRACE_SENSITIVITY_INPUT, input, sizeof(input) - 1u);
    rdp_trace_hexdump("client.smartcard.apdu", RDP_TRACE_SENSITIVITY_APDU, apdu, sizeof(apdu) - 1u);
    rdp_trace_hexdump("client.usb.urb", RDP_TRACE_SENSITIVITY_USB, usb, sizeof(usb) - 1u);
    rdp_trace_hexdump("client.audio.pdu", RDP_TRACE_SENSITIVITY_AUDIO, audio, sizeof(audio) - 1u);
    rdp_trace_hexdump("client.media.pdu", RDP_TRACE_SENSITIVITY_VIDEO, media, sizeof(media) - 1u);
    unsetenv("LIBRDP_TRACE_PROTOCOL");
    unsetenv("LIBRDP_TRACE_LEVEL");
    unsetenv("LIBRDP_TRACE_HEX_BYTES");
}

static void trace_sensitive_hexdumps_unsafe(void)
{
    const uint8_t password[] = "HDR:LIBRDP_PASSWORD_CANARY";
    const uint8_t input[] = "HDR:LIBRDP_INPUT_CANARY";

    setenv("LIBRDP_TRACE_PROTOCOL", "1", 1);
    setenv("LIBRDP_TRACE_LEVEL", "trace", 1);
    setenv("LIBRDP_TRACE_HEX_BYTES", "96", 1);
    setenv("LIBRDP_TRACE_UNSAFE", "1", 1);
    rdp_trace_reset_for_tests();
    rdp_trace_hexdump("rdp.client_info.pdu", RDP_TRACE_SENSITIVITY_AUTH, password, sizeof(password) - 1u);
    rdp_trace_hexdump("client.input.send", RDP_TRACE_SENSITIVITY_INPUT, input, sizeof(input) - 1u);
    unsetenv("LIBRDP_TRACE_PROTOCOL");
    unsetenv("LIBRDP_TRACE_LEVEL");
    unsetenv("LIBRDP_TRACE_HEX_BYTES");
    unsetenv("LIBRDP_TRACE_UNSAFE");
}

static void trace_level_filtered_event(void)
{
    setenv("LIBRDP_TRACE_CLIENT", "1", 1);
    setenv("LIBRDP_TRACE_LEVEL", "info", 1);
    rdp_trace_reset_for_tests();
    rdp_trace_event_level(RDP_TRACE_CLIENT, RDP_TRACE_LEVEL_DEBUG, "client.debug", "value=1");
    unsetenv("LIBRDP_TRACE_CLIENT");
    unsetenv("LIBRDP_TRACE_LEVEL");
}

static void trace_level_debug_event(void)
{
    setenv("LIBRDP_TRACE_CLIENT", "1", 1);
    setenv("LIBRDP_TRACE_LEVEL", "debug", 1);
    rdp_trace_reset_for_tests();
    rdp_trace_event_level(RDP_TRACE_CLIENT, RDP_TRACE_LEVEL_DEBUG, "client.debug", "value=1");
    unsetenv("LIBRDP_TRACE_CLIENT");
    unsetenv("LIBRDP_TRACE_LEVEL");
}

/*
 * Coverage: validates trace environment parsing, category filtering, monotonic
 * formatting, redaction boundaries, and bounded hexdump behavior.
 */
int test_trace(void)
{
    rdp_trace_session_scope outer_scope;
    rdp_trace_session_scope inner_scope;
    char output[4096];

    CHECK(rdp_trace_parse_bool_value("1"));
    CHECK(rdp_trace_parse_bool_value("true"));
    CHECK(rdp_trace_parse_bool_value("TRUE"));
    CHECK(rdp_trace_parse_bool_value("yes"));
    CHECK(rdp_trace_parse_bool_value("YES"));
    CHECK(rdp_trace_parse_bool_value("on"));
    CHECK(rdp_trace_parse_bool_value("ON"));
    CHECK(!rdp_trace_parse_bool_value("0"));
    CHECK(!rdp_trace_parse_bool_value("maybe"));
    CHECK(rdp_trace_parse_hex_limit_value("32") == 32);
    CHECK(rdp_trace_parse_hex_limit_value("bad") == 0);
    CHECK(rdp_trace_parse_hex_limit_value("") == 0);
    CHECK(rdp_trace_parse_level_value(NULL) == RDP_TRACE_LEVEL_INFO);
    CHECK(rdp_trace_parse_level_value("") == RDP_TRACE_LEVEL_INFO);
    CHECK(rdp_trace_parse_level_value("error") == RDP_TRACE_LEVEL_ERROR);
    CHECK(rdp_trace_parse_level_value("WARN") == RDP_TRACE_LEVEL_WARN);
    CHECK(rdp_trace_parse_level_value("info") == RDP_TRACE_LEVEL_INFO);
    CHECK(rdp_trace_parse_level_value("debug") == RDP_TRACE_LEVEL_DEBUG);
    CHECK(rdp_trace_parse_level_value("TRACE") == RDP_TRACE_LEVEL_TRACE);
    CHECK(rdp_trace_parse_level_value("bad") == RDP_TRACE_LEVEL_INFO);

    memset(&outer_scope, 0, sizeof(outer_scope));
    memset(&inner_scope, 0, sizeof(inner_scope));
    outer_scope.categories = RDP_TRACE_CLIENT;
    outer_scope.level = RDP_TRACE_LEVEL_INFO;
    outer_scope.sink = LIBRDP_TRACE_SINK_STDERR;
    inner_scope.categories = RDP_TRACE_TRANSPORT;
    inner_scope.level = RDP_TRACE_LEVEL_INFO;
    inner_scope.sink = LIBRDP_TRACE_SINK_STDERR;
    rdp_trace_reset_for_tests();
    rdp_trace_push_session(&outer_scope);
    CHECK(rdp_trace_enabled(RDP_TRACE_CLIENT));
    CHECK(!rdp_trace_enabled(RDP_TRACE_TRANSPORT));
    rdp_trace_push_session(&inner_scope);
    CHECK(!rdp_trace_enabled(RDP_TRACE_CLIENT));
    CHECK(rdp_trace_enabled(RDP_TRACE_TRANSPORT));
    rdp_trace_pop_session(&outer_scope);
    CHECK(!rdp_trace_enabled(RDP_TRACE_CLIENT));
    CHECK(rdp_trace_enabled(RDP_TRACE_TRANSPORT));
    rdp_trace_pop_session(&inner_scope);
    CHECK(rdp_trace_enabled(RDP_TRACE_CLIENT));
    CHECK(!rdp_trace_enabled(RDP_TRACE_TRANSPORT));
    rdp_trace_pop_session(&outer_scope);

    unsetenv("LIBRDP_TRACE_CLIENT");
    unsetenv("LIBRDP_TRACE_LEVEL");
    rdp_trace_reset_for_tests();
    CHECK(!rdp_trace_enabled(RDP_TRACE_CLIENT));
    setenv("LIBRDP_TRACE_CLIENT", "true", 1);
    rdp_trace_refresh_from_env();
    CHECK(rdp_trace_enabled(RDP_TRACE_CLIENT));
    unsetenv("LIBRDP_TRACE_CLIENT");
    rdp_trace_refresh_from_env();
    CHECK(!rdp_trace_enabled(RDP_TRACE_CLIENT));
    CHECK(capture_stderr(trace_default_event, output, sizeof(output)));
    CHECK(output[0] == '\0');

    CHECK(capture_stderr(trace_enabled_event, output, sizeof(output)));
    CHECK(strstr(output, "librdp trace seq=1 ") != NULL);
    CHECK(strstr(output, "category=client event=client.test") != NULL);
    CHECK(strstr(output, "message=\"value=1\"") != NULL);

    setenv("LIBRDP_TRACE_TRANSPORT", "1", 1);
    rdp_trace_reset_for_tests();
    CHECK(rdp_trace_enabled(RDP_TRACE_TRANSPORT));
    CHECK(!rdp_trace_enabled(RDP_TRACE_CLIENT));
    CHECK(rdp_trace_enabled_level(RDP_TRACE_TRANSPORT, RDP_TRACE_LEVEL_INFO));
    CHECK(!rdp_trace_enabled_level(RDP_TRACE_TRANSPORT, RDP_TRACE_LEVEL_DEBUG));
    unsetenv("LIBRDP_TRACE_TRANSPORT");

    CHECK(capture_stderr(trace_level_filtered_event, output, sizeof(output)));
    CHECK(output[0] == '\0');
    CHECK(capture_stderr(trace_level_debug_event, output, sizeof(output)));
    CHECK(strstr(output, "category=client event=client.debug level=debug") != NULL);

    CHECK(capture_stderr(trace_protocol_hexdump, output, sizeof(output)));
    CHECK(strstr(output, "category=protocol event=rdp.fastpath.pdu") != NULL);
    CHECK(strstr(output, "level=trace") != NULL);
    CHECK(strstr(output, "payload_len=4 dumped=2 hex=4142 ascii=\"AB\"") != NULL);
    CHECK(strstr(output, "sensitivity=header redacted=0 unsafe=0") != NULL);

    CHECK(capture_stderr(trace_sensitive_hexdumps, output, sizeof(output)));
    CHECK(strstr(output, "sensitivity=auth redacted=1 unsafe=0") != NULL);
    CHECK(strstr(output, "sensitivity=input redacted=1 unsafe=0") != NULL);
    CHECK(strstr(output, "LIBRDP_IDENTITY_CANARY") == NULL);
    CHECK(strstr(output, "LIBRDP_PASSWORD_CANARY") == NULL);
    CHECK(strstr(output, "LIBRDP_CREDSSP_TOKEN_CANARY") == NULL);
    CHECK(strstr(output, "LIBRDP_CLIPBOARD_CANARY") == NULL);
    CHECK(strstr(output, "LIBRDP_INPUT_CANARY") == NULL);
    CHECK(strstr(output, "LIBRDP_APDU_CANARY") == NULL);
    CHECK(strstr(output, "LIBRDP_USB_CANARY") == NULL);
    CHECK(strstr(output, "LIBRDP_AUDIO_CANARY") == NULL);
    CHECK(strstr(output, "LIBRDP_MEDIA_CANARY") == NULL);
    CHECK(strstr(output, "4c49425244505f50415353574f52445f43414e415259") == NULL);
    CHECK(strstr(output, "4c49425244505f494e5055545f43414e415259") == NULL);

    CHECK(capture_stderr(trace_sensitive_hexdumps_unsafe, output, sizeof(output)));
    CHECK(strstr(output, "sensitivity=auth redacted=0 unsafe=1") != NULL);
    CHECK(strstr(output, "LIBRDP_PASSWORD_CANARY") != NULL);
    CHECK(strstr(output, "LIBRDP_INPUT_CANARY") != NULL);
    return 0;
}

int test_buffer_stream(void)
{
    rdp_buffer buffer;
    rdp_stream stream;
    uint8_t u8 = 0;
    uint16_t u16 = 0;
    uint32_t u32 = 0;
    const uint8_t* raw = NULL;

    rdp_buffer_init(&buffer);
    CHECK(rdp_buffer_reserve(NULL, 1) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(rdp_buffer_reserve(&buffer, 32) == LIBRDP_STATUS_OK);
    CHECK(buffer.capacity >= 32);
    CHECK(buffer.length == 0);
    CHECK(rdp_buffer_append_u8(&buffer, 0x11) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u16_le(&buffer, 0x2233) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u16_be(&buffer, 0x4455) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_le(&buffer, 0x66778899u) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u32_be(&buffer, 0xaabbccddu) == LIBRDP_STATUS_OK);
    CHECK(buffer.length == 13);

    rdp_stream_init(&stream, buffer.data, buffer.length);
    CHECK(rdp_stream_read_u8(&stream, &u8) == LIBRDP_STATUS_OK && u8 == 0x11);
    CHECK(rdp_stream_read_u16_le(&stream, &u16) == LIBRDP_STATUS_OK && u16 == 0x2233);
    CHECK(rdp_stream_read_u16_be(&stream, &u16) == LIBRDP_STATUS_OK && u16 == 0x4455);
    CHECK(rdp_stream_read_u32_le(&stream, &u32) == LIBRDP_STATUS_OK && u32 == 0x66778899u);
    CHECK(rdp_stream_read_u32_be(&stream, &u32) == LIBRDP_STATUS_OK && u32 == 0xaabbccddu);
    CHECK(rdp_stream_read_u8(&stream, &u8) == LIBRDP_STATUS_PROTOCOL_ERROR);

    CHECK(rdp_buffer_consume(&buffer, 3) == LIBRDP_STATUS_OK);
    CHECK(buffer.length == 10);
    rdp_stream_init(&stream, buffer.data, buffer.length);
    CHECK(rdp_stream_read_bytes(&stream, &raw, 2) == LIBRDP_STATUS_OK);
    CHECK(raw[0] == 0x44 && raw[1] == 0x55);
    CHECK(rdp_stream_skip(&stream, 100) == LIBRDP_STATUS_PROTOCOL_ERROR);

    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    CHECK(rdp_buffer_append_u8(&buffer, 0) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u8(&buffer, 1) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u8(&buffer, 2) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u8(&buffer, 3) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u8(&buffer, 4) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append_u8(&buffer, 5) == LIBRDP_STATUS_OK);
    CHECK(rdp_buffer_append(&buffer, buffer.data + 1u, 4u) == LIBRDP_STATUS_OK);
    CHECK(buffer.length == 10u);
    CHECK(buffer.data[6] == 1u && buffer.data[7] == 2u && buffer.data[8] == 3u && buffer.data[9] == 4u);
    buffer.length = 0;
    CHECK(rdp_buffer_append(&buffer, buffer.data + 6u, 4u) == LIBRDP_STATUS_OK);
    CHECK(buffer.length == 4u);
    CHECK(buffer.data[0] == 1u && buffer.data[1] == 2u && buffer.data[2] == 3u && buffer.data[3] == 4u);

    rdp_buffer_free(&buffer);
    buffer.capacity = 8u;
    CHECK(rdp_buffer_reserve(&buffer, 4u) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(rdp_buffer_append_u8(&buffer, 1u) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(rdp_buffer_consume(&buffer, 0u) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_init(&buffer);
    buffer.length = 1u;
    CHECK(rdp_buffer_reserve(&buffer, 1u) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(rdp_buffer_append(&buffer, NULL, 0u) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(rdp_buffer_consume(&buffer, 0u) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_init(&buffer);
    return 0;
}

int test_charset(void)
{
    static const uint8_t utf16_expected[] = {
        0x41, 0x00, 0xe9, 0x00, 0x3d, 0xd8, 0x00, 0xde, 0x00, 0x00
    };
    static const uint8_t utf16_input[] = {
        0x41, 0x00, 0xe9, 0x00, 0x3d, 0xd8, 0x00, 0xde, 0x00, 0x00, 0x42, 0x00
    };
    rdp_buffer buffer;
    char* utf8 = NULL;
    size_t utf8_len = 0;
    uint8_t* utf16 = NULL;
    size_t utf16_len = 0;

    rdp_buffer_init(&buffer);
    CHECK(rdp_charset_utf8_to_utf16le_buffer("A\303\251\360\237\230\200", 1, &buffer) ==
          LIBRDP_STATUS_OK);
    CHECK(buffer.length == sizeof(utf16_expected));
    CHECK(memcmp(buffer.data, utf16_expected, sizeof(utf16_expected)) == 0);
    rdp_buffer_free(&buffer);

    CHECK(rdp_charset_utf16le_to_utf8_alloc(utf16_input, sizeof(utf16_input), 1, &utf8, &utf8_len) ==
          LIBRDP_STATUS_OK);
    CHECK(utf8_len == 7);
    CHECK(memcmp(utf8, "A\303\251\360\237\230\200", utf8_len) == 0);
    free(utf8);

    CHECK(rdp_charset_utf8_bytes_to_utf16le_alloc((const uint8_t*)"AB", 2, 0, &utf16, &utf16_len) ==
          LIBRDP_STATUS_OK);
    CHECK(utf16_len == 4);
    CHECK(utf16[0] == 'A' && utf16[1] == 0 && utf16[2] == 'B' && utf16[3] == 0);
    free(utf16);
    return 0;
}

int test_pointer_decode(void)
{
    rdp_pointer_update update;
    rdp_buffer output;
    size_t stride = 0;
    const uint8_t xor_mask[12] = {
        0, 0, 0, 0,
        0xff, 0xff, 0xff, 0,
        0, 0, 0, 0
    };
    const uint8_t and_mask[2] = {0xe0, 0};
    const uint8_t xor_mask_24[4] = {0xff, 0xff, 0xff, 0};
    const uint8_t and_mask_24[2] = {0x80, 0};

    memset(&update, 0, sizeof(update));
    rdp_buffer_init(&output);
    update.kind = RDP_POINTER_UPDATE_KIND_SHAPE;
    update.width = 3;
    update.height = 1;
    update.xor_bpp = 32;
    update.xor_mask = xor_mask;
    update.xor_mask_len = sizeof(xor_mask);
    update.and_mask = and_mask;
    update.and_mask_len = sizeof(and_mask);

    CHECK(rdp_pointer_decode_bgra32(&update, &output, &stride) == LIBRDP_STATUS_OK);
    CHECK(stride == 12);
    CHECK(output.length == 12);
    CHECK(output.data[0] == 0 && output.data[1] == 0 && output.data[2] == 0 && output.data[3] == 0);
    CHECK(output.data[4] == 0 && output.data[5] == 0 && output.data[6] == 0 && output.data[7] == 0xff);
    CHECK(output.data[8] == 0 && output.data[9] == 0 && output.data[10] == 0 && output.data[11] == 0);

    rdp_buffer_free(&output);
    rdp_buffer_init(&output);
    memset(&update, 0, sizeof(update));
    update.kind = RDP_POINTER_UPDATE_KIND_SHAPE;
    update.width = 1;
    update.height = 1;
    update.xor_bpp = 24;
    update.xor_mask = xor_mask_24;
    update.xor_mask_len = sizeof(xor_mask_24);
    update.and_mask = and_mask_24;
    update.and_mask_len = sizeof(and_mask_24);

    CHECK(rdp_pointer_decode_bgra32(&update, &output, &stride) == LIBRDP_STATUS_OK);
    CHECK(stride == 4);
    CHECK(output.length == 4);
    CHECK(output.data[0] == 0 && output.data[1] == 0 && output.data[2] == 0 && output.data[3] == 0xff);
    rdp_buffer_free(&output);
    return 0;
}
