#include <librdp/librdp.h>

#include "common/buffer.h"
#include "common/stream.h"
#include "common/trace.h"
#include "input/input.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expr)                                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

typedef struct event_counter
{
    int states;
    int surfaces;
    int keys;
    int mouse;
    int disconnected;
} event_counter;

int test_protocol(void);
int test_transport(void);

static void on_event(librdp_session* session, const librdp_event* event, void* user_data)
{
    event_counter* counter = (event_counter*)user_data;
    (void)session;

    if (!event || !counter)
        return;

    switch (event->type)
    {
        case LIBRDP_EVENT_STATE_CHANGED:
            counter->states++;
            break;
        case LIBRDP_EVENT_SURFACE_INVALIDATED:
            counter->surfaces++;
            break;
        case LIBRDP_EVENT_KEY_SENT:
            counter->keys++;
            break;
        case LIBRDP_EVENT_MOUSE_SENT:
            counter->mouse++;
            break;
        case LIBRDP_EVENT_DISCONNECTED:
            counter->disconnected++;
            break;
        default:
            break;
    }
}

static int capture_stderr(void (*fn)(void), char* out, size_t out_len)
{
    int pipe_fds[2] = {-1, -1};
    int saved = -1;
    ssize_t got = 0;

    if (pipe(pipe_fds) != 0)
        return 0;
    saved = dup(STDERR_FILENO);
    if (saved < 0)
        return 0;
    if (dup2(pipe_fds[1], STDERR_FILENO) < 0)
        return 0;
    close(pipe_fds[1]);

    fn();
    fflush(stderr);

    if (dup2(saved, STDERR_FILENO) < 0)
        return 0;
    close(saved);

    got = read(pipe_fds[0], out, out_len - 1);
    close(pipe_fds[0]);
    if (got < 0)
        got = 0;
    out[got] = '\0';
    return 1;
}

static int read_exact_fd(int fd, void* data, size_t length)
{
    uint8_t* out = (uint8_t*)data;
    size_t offset = 0;

    while (offset < length)
    {
        ssize_t got = read(fd, out + offset, length - offset);
        if (got <= 0)
            return 0;
        offset += (size_t)got;
    }

    return 1;
}

static int write_exact_fd(int fd, const void* data, size_t length)
{
    const uint8_t* in = (const uint8_t*)data;
    size_t offset = 0;

    while (offset < length)
    {
        ssize_t wrote = write(fd, in + offset, length - offset);
        if (wrote <= 0)
            return 0;
        offset += (size_t)wrote;
    }

    return 1;
}

static int read_tpkt_fd(int fd, uint8_t* data, size_t capacity, size_t* length)
{
    uint16_t total = 0;

    if (!data || capacity < 4 || !length)
        return 0;
    if (!read_exact_fd(fd, data, 4))
        return 0;
    total = (uint16_t)(((uint16_t)data[2] << 8) | data[3]);
    if (data[0] != 3 || data[1] != 0 || total < 4 || total > capacity)
        return 0;
    if (!read_exact_fd(fd, data + 4, (size_t)total - 4u))
        return 0;
    *length = total;
    return 1;
}

static int start_handshake_server(uint16_t* port, pid_t* child_pid)
{
    int fd = -1;
    struct sockaddr_in addr;
    socklen_t addr_len = (socklen_t)sizeof(addr);

    if (!port || !child_pid)
        return 0;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        getsockname(fd, (struct sockaddr*)&addr, &addr_len) != 0 ||
        listen(fd, 1) != 0)
    {
        close(fd);
        return 0;
    }

    *port = ntohs(addr.sin_port);
    *child_pid = fork();
    if (*child_pid < 0)
    {
        close(fd);
        return 0;
    }

    if (*child_pid == 0)
    {
        uint8_t input[4096];
        size_t input_len = 0;
        const uint8_t response[] = {
            0x03, 0x00, 0x00, 0x13,
            0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x08, 0x00,
            0x00, 0x00, 0x00, 0x00
        };
        const uint8_t mcs_response[] = {
            0x03, 0x00, 0x00, 0x4b,
            0x02, 0xf0, 0x80,
            0x7f, 0x66, 0x41, 0x0a, 0x01, 0x00, 0x04, 0x3c,
            0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01, 0x34, 0x14, 0x00, 0x03, 0x01,
            0x2a, 0x00, 0x01, 0xc0, 0x00, 'M',  'c',  'D',  'n',  0x26,
            0x01, 0x0c, 0x10, 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x0c, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x03, 0x0c, 0x0a, 0x00, 0xeb, 0x03, 0x01, 0x00,
            0xec, 0x03
        };
        const uint8_t attach_confirm[] = {
            0x03, 0x00, 0x00, 0x0b,
            0x02, 0xf0, 0x80,
            0x2e, 0x00, 0x00, 0x03
        };
        const uint8_t join_user_confirm[] = {
            0x03, 0x00, 0x00, 0x0f,
            0x02, 0xf0, 0x80,
            0x3e, 0x00, 0x00, 0x03, 0x03, 0xec, 0x03, 0xec
        };
        const uint8_t join_global_confirm[] = {
            0x03, 0x00, 0x00, 0x0f,
            0x02, 0xf0, 0x80,
            0x3e, 0x00, 0x00, 0x03, 0x03, 0xeb, 0x03, 0xeb
        };
        struct timespec ts;
        int client = accept(fd, NULL, NULL);
        if (client >= 0)
        {
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            (void)write_exact_fd(client, response, sizeof(response));
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            (void)write_exact_fd(client, mcs_response, sizeof(mcs_response));
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            (void)write_exact_fd(client, attach_confirm, sizeof(attach_confirm));
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            (void)write_exact_fd(client, join_user_confirm, sizeof(join_user_confirm));
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            (void)write_exact_fd(client, join_global_confirm, sizeof(join_global_confirm));
            (void)read_tpkt_fd(client, input, sizeof(input), &input_len);
            ts.tv_sec = 1;
            ts.tv_nsec = 0;
            (void)nanosleep(&ts, NULL);
            close(client);
        }
        close(fd);
        _exit(0);
    }

    close(fd);
    return 1;
}

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
    setenv("LIBRDP_TRACE_HEX_BYTES", "2", 1);
    rdp_trace_reset_for_tests();
    rdp_trace_hexdump("rdp.fastpath.pdu", bytes, sizeof(bytes));
    unsetenv("LIBRDP_TRACE_PROTOCOL");
    unsetenv("LIBRDP_TRACE_HEX_BYTES");
}

static int test_trace(void)
{
    char output[2048];

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

    unsetenv("LIBRDP_TRACE_CLIENT");
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
    unsetenv("LIBRDP_TRACE_TRANSPORT");

    CHECK(capture_stderr(trace_protocol_hexdump, output, sizeof(output)));
    CHECK(strstr(output, "category=protocol event=rdp.fastpath.pdu") != NULL);
    CHECK(strstr(output, "payload_len=4 dumped=2 hex=4142 ascii=\"AB\"") != NULL);
    return 0;
}

static int test_buffer_stream(void)
{
    rdp_buffer buffer;
    rdp_stream stream;
    uint8_t u8 = 0;
    uint16_t u16 = 0;
    uint32_t u32 = 0;
    const uint8_t* raw = NULL;

    rdp_buffer_init(&buffer);
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
    return 0;
}

static int test_settings_surface_input_session(void)
{
    librdp_settings* settings = NULL;
    librdp_settings* copy = NULL;
    librdp_surface* surface = NULL;
    librdp_session* session = NULL;
    const librdp_surface* session_surface = NULL;
    uint8_t pixels[16] = {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16
    };
    const uint8_t* out = NULL;
    uint16_t flags = 0;
    librdp_key_event key = {30, LIBRDP_KEY_PRESSED};
    librdp_mouse_event mouse = {10, 11, LIBRDP_MOUSE_BUTTON_LEFT, LIBRDP_MOUSE_PRESSED};
    event_counter counter;
    uint16_t test_port = 0;
    pid_t server_pid = -1;

    memset(&counter, 0, sizeof(counter));

    CHECK(strcmp(librdp_status_string(LIBRDP_STATUS_OK), "ok") == 0);
    CHECK(strcmp(librdp_status_string((librdp_status)-1000), "unknown") == 0);

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_port(settings) == 3389);
    CHECK(librdp_settings_width(settings) == 1024);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_username(settings, "user") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_password(settings, "secret") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_domain(settings, "domain") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_port(settings, 3390) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_desktop_size(settings, 64, 48) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_TLS) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_port(settings, 0) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_desktop_size(settings, 0, 48) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(librdp_settings_set_security_mode(settings, (librdp_security_mode)99) == LIBRDP_STATUS_INVALID_ARGUMENT);

    copy = librdp_settings_clone(settings);
    CHECK(copy != NULL);
    CHECK(strcmp(librdp_settings_target(copy), "127.0.0.1") == 0);
    CHECK(strcmp(librdp_settings_username(copy), "user") == 0);
    CHECK(strcmp(librdp_settings_domain(copy), "domain") == 0);
    CHECK(librdp_settings_security_mode(copy) == LIBRDP_SECURITY_TLS);

    surface = librdp_surface_new(4, 4, LIBRDP_PIXEL_FORMAT_BGRA32);
    CHECK(surface != NULL);
    CHECK(librdp_surface_stride(surface) == 16);
    CHECK(librdp_surface_blit_bgra32(surface, 1, 1, 2, 2, pixels, 8) == LIBRDP_STATUS_OK);
    CHECK(librdp_surface_blit_bgra32(surface, 3, 3, 2, 2, pixels, 8) == LIBRDP_STATUS_INVALID_ARGUMENT);
    out = librdp_surface_pixels(surface);
    CHECK(out[((size_t)1 * 16) + 4] == 1);
    CHECK(librdp_surface_resize(surface, 2, 2) == LIBRDP_STATUS_OK);
    CHECK(librdp_surface_width(surface) == 2);
    CHECK(librdp_surface_pixels_mut(surface) != NULL);
    librdp_surface_free(surface);

    CHECK(rdp_input_make_keyboard_flags(&key, &flags) == LIBRDP_STATUS_OK && flags == 0);
    key.state = LIBRDP_KEY_RELEASED;
    CHECK(rdp_input_make_keyboard_flags(&key, &flags) == LIBRDP_STATUS_OK && flags == 0x8000u);
    CHECK(rdp_input_make_pointer_flags(&mouse, &flags) == LIBRDP_STATUS_OK && (flags & 0x9000u) == 0x9000u);

    session = librdp_session_new(settings);
    CHECK(session != NULL);
    CHECK(start_handshake_server(&test_port, &server_pid));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    librdp_session_free(session);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    librdp_session_set_event_callback(session, on_event, &counter);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_CONNECTED);
    CHECK(counter.states == 2);
    CHECK(counter.surfaces == 1);
    session_surface = librdp_session_get_surface(session);
    CHECK(session_surface != NULL);
    CHECK(librdp_surface_width(session_surface) == 64);
    CHECK(librdp_session_run_once(session, 0) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_ACTIVE);
    key.state = LIBRDP_KEY_PRESSED;
    CHECK(librdp_session_send_key(session, &key) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_send_mouse(session, &mouse) == LIBRDP_STATUS_OK);
    CHECK(counter.keys == 1);
    CHECK(counter.mouse == 1);
    CHECK(librdp_session_resize(session, 80, 60) == LIBRDP_STATUS_OK);
    CHECK(counter.surfaces == 2);
    CHECK(librdp_session_disconnect(session) == LIBRDP_STATUS_OK);
    CHECK(counter.disconnected == 1);
    librdp_session_free(session);
    if (server_pid > 0)
        (void)waitpid(server_pid, NULL, 0);

    librdp_settings_free(copy);
    librdp_settings_free(settings);
    return 0;
}

int main(void)
{
    if (test_trace() != 0)
        return 1;
    if (test_buffer_stream() != 0)
        return 1;
    if (test_protocol() != 0)
        return 1;
    if (test_transport() != 0)
        return 1;
    if (test_settings_surface_input_session() != 0)
        return 1;
    return 0;
}
