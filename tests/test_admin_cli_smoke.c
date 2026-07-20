/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: administration CLI loopback smoke tests.
 * Coverage: the real headless administration application queries a synthetic
 * WinRM inventory and executes message, disconnect, and logoff actions.
 * Bug classes: CLI-to-API wiring loss, malformed SOAP commands, missing
 * confirmation, stale inventory state, timeout hangs, and trace data leaks.
 * Determinism: each invocation uses one loopback HTTP exchange, bounded process
 * execution, synthetic identities, and an in-memory disposable session state.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ADMIN_SMOKE_SESSION_ID 42u
#define ADMIN_SMOKE_IO_TIMEOUT_MS 5000
#define ADMIN_SMOKE_PROCESS_TIMEOUT_NS 10000000000ULL
#define ADMIN_SMOKE_REQUEST_CAPACITY 16384u
#define ADMIN_SMOKE_OUTPUT_CAPACITY 32768u

typedef enum admin_smoke_request_kind
{
    ADMIN_SMOKE_QUERY = 0,
    ADMIN_SMOKE_MESSAGE = 1,
    ADMIN_SMOKE_DISCONNECT = 2,
    ADMIN_SMOKE_LOGOFF = 3
} admin_smoke_request_kind;

typedef struct admin_smoke_state
{
    int logged_on;
    int connected;
    unsigned int messages;
} admin_smoke_state;

typedef struct admin_smoke_result
{
    char output[ADMIN_SMOKE_OUTPUT_CAPACITY];
    size_t output_len;
    int exit_code;
    int request_valid;
} admin_smoke_result;

static uint64_t admin_smoke_now_ns(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0u;
    return (uint64_t)now.tv_sec * 1000000000ULL +
           (uint64_t)now.tv_nsec;
}

static int admin_smoke_write_all(int fd,
                                 const void* data,
                                 size_t length)
{
    const uint8_t* bytes = (const uint8_t*)data;
    size_t offset = 0u;

    while (offset < length)
    {
        ssize_t count = write(fd, bytes + offset, length - offset);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return 0;
        offset += (size_t)count;
    }
    return 1;
}

static int admin_smoke_listen(uint16_t* port)
{
    struct sockaddr_in address;
    socklen_t address_len = (socklen_t)sizeof(address);
    int fd = -1;
    int one = 1;

    if (!port)
        return -1;
    *port = 0u;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0u;
    if (bind(fd,
             (const struct sockaddr*)&address,
             sizeof(address)) != 0 ||
        getsockname(fd,
                    (struct sockaddr*)&address,
                    &address_len) != 0 ||
        listen(fd, 1) != 0)
    {
        close(fd);
        return -1;
    }
    *port = ntohs(address.sin_port);
    return fd;
}

static int admin_smoke_content_length(const char* request,
                                      size_t header_len,
                                      size_t* content_len)
{
    static const char field[] = "Content-Length:";
    const char* cursor = request;
    const char* header_end = request + header_len;

    if (!request || !content_len)
        return 0;
    while (cursor < header_end)
    {
        const char* line_end = strstr(cursor, "\r\n");

        if (!line_end || line_end > header_end)
            return 0;
        if ((size_t)(line_end - cursor) >= sizeof(field) - 1u &&
            strncasecmp(cursor, field, sizeof(field) - 1u) == 0)
        {
            char* end = NULL;
            unsigned long parsed = 0u;

            cursor += sizeof(field) - 1u;
            while (cursor < line_end &&
                   (*cursor == ' ' || *cursor == '\t'))
                cursor++;
            errno = 0;
            parsed = strtoul(cursor, &end, 10);
            if (errno != 0 || !end || end == cursor ||
                end != line_end || parsed > ADMIN_SMOKE_REQUEST_CAPACITY)
                return 0;
            *content_len = (size_t)parsed;
            return 1;
        }
        cursor = line_end + 2;
    }
    return 0;
}

/*
 * Read one complete HTTP request by honoring Content-Length. This avoids
 * accepting a partial SOAP body merely because the TCP segmentation happened
 * to place the header and an XML prefix in the same read.
 */
static int admin_smoke_read_request(int listen_fd,
                                    char* request,
                                    size_t request_capacity,
                                    int* client_fd)
{
    struct pollfd wait_fd;
    char* headers_end = NULL;
    size_t content_len = 0u;
    size_t expected = 0u;
    size_t used = 0u;
    int client = -1;

    if (listen_fd < 0 || !request || request_capacity < 2u || !client_fd)
        return 0;
    *client_fd = -1;
    memset(&wait_fd, 0, sizeof(wait_fd));
    wait_fd.fd = listen_fd;
    wait_fd.events = POLLIN;
    if (poll(&wait_fd, 1u, ADMIN_SMOKE_IO_TIMEOUT_MS) != 1)
        return 0;
    client = accept(listen_fd, NULL, NULL);
    if (client < 0)
        return 0;
    for (;;)
    {
        ssize_t count = 0;

        if (used + 1u >= request_capacity)
        {
            close(client);
            return 0;
        }
        count = read(client,
                     request + used,
                     request_capacity - used - 1u);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
        {
            close(client);
            return 0;
        }
        used += (size_t)count;
        request[used] = '\0';
        headers_end = strstr(request, "\r\n\r\n");
        if (headers_end && expected == 0u)
        {
            size_t header_len = (size_t)(headers_end - request) + 4u;

            if (!admin_smoke_content_length(request,
                                            header_len,
                                            &content_len) ||
                content_len > request_capacity - header_len - 1u)
            {
                close(client);
                return 0;
            }
            expected = header_len + content_len;
        }
        if (expected > 0u && used >= expected)
        {
            *client_fd = client;
            return used == expected;
        }
    }
}

static int admin_smoke_request_matches(
    admin_smoke_request_kind kind,
    const char* request)
{
    const char* expected = NULL;

    if (!request || !strstr(request, "POST /wsman HTTP/") ||
        !strstr(request, "</s:Envelope>"))
        return 0;
    switch (kind)
    {
        case ADMIN_SMOKE_QUERY:
            return strstr(request, "<n:Enumerate/>") != NULL;
        case ADMIN_SMOKE_MESSAGE:
            expected =
                "<p:CommandLine>msg 42 /TIME:60 "
                "&quot;Smoke notice: maintenance window&quot;"
                "</p:CommandLine>";
            break;
        case ADMIN_SMOKE_DISCONNECT:
            expected =
                "<p:CommandLine>tsdiscon 42</p:CommandLine>";
            break;
        case ADMIN_SMOKE_LOGOFF:
            expected = "<p:CommandLine>logoff 42</p:CommandLine>";
            break;
        default:
            return 0;
    }
    return strstr(request, "Win32_Process/Create") != NULL &&
           strstr(request, expected) != NULL;
}

static int admin_smoke_response_body(admin_smoke_request_kind kind,
                                     const admin_smoke_state* state,
                                     char* body,
                                     size_t body_capacity)
{
    int written = 0;

    if (!state || !body || body_capacity == 0u)
        return 0;
    if (kind == ADMIN_SMOKE_QUERY)
    {
        const char* session = "";
        char session_buffer[768];

        session_buffer[0] = '\0';
        if (state->logged_on)
        {
            written = snprintf(
                session_buffer,
                sizeof(session_buffer),
                "<Session><SessionId>%u</SessionId>"
                "<LogonId>42001</LogonId>"
                "<UserName>smoke-user</UserName>"
                "<Domain>SMOKE-DOMAIN</Domain>"
                "<State>%s</State>"
                "<ClientName>smoke-client</ClientName>"
                "<WinStationName>rdp-tcp#smoke</WinStationName>"
                "<ProtocolName>rdp</ProtocolName></Session>",
                ADMIN_SMOKE_SESSION_ID,
                state->connected ? "Active" : "Disconnected");
            if (written <= 0 ||
                (size_t)written >= sizeof(session_buffer))
                return 0;
            session = session_buffer;
        }
        written = snprintf(
            body,
            body_capacity,
            "<s:Envelope "
            "xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
            "<s:Body><Sessions>%s</Sessions></s:Body></s:Envelope>",
            session);
    }
    else
    {
        written = snprintf(
            body,
            body_capacity,
            "<s:Envelope "
            "xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
            "<s:Body><p:Create_OUTPUT "
            "xmlns:p=\"http://schemas.microsoft.com/wbem/wsman/1/wmi/"
            "root/cimv2/Win32_Process\">"
            "<p:ReturnValue>0</p:ReturnValue>"
            "</p:Create_OUTPUT></s:Body></s:Envelope>");
    }
    return written > 0 && (size_t)written < body_capacity;
}

static int admin_smoke_serve(int listen_fd,
                             admin_smoke_request_kind kind,
                             admin_smoke_state* state,
                             int* request_valid)
{
    char body[2048];
    char header[256];
    char request[ADMIN_SMOKE_REQUEST_CAPACITY];
    int client = -1;
    int header_len = 0;
    int valid = 0;

    if (!state || !request_valid)
        return 0;
    *request_valid = 0;
    if (!admin_smoke_read_request(listen_fd,
                                  request,
                                  sizeof(request),
                                  &client))
        return 0;
    valid = admin_smoke_request_matches(kind, request);
    if (valid)
    {
        if (kind == ADMIN_SMOKE_MESSAGE)
            state->messages++;
        else if (kind == ADMIN_SMOKE_DISCONNECT)
            state->connected = 0;
        else if (kind == ADMIN_SMOKE_LOGOFF)
        {
            state->logged_on = 0;
            state->connected = 0;
        }
    }
    if (!admin_smoke_response_body(kind, state, body, sizeof(body)))
    {
        close(client);
        return 0;
    }
    header_len = snprintf(header,
                          sizeof(header),
                          "HTTP/1.1 200 OK\r\n"
                          "Content-Type: application/soap+xml\r\n"
                          "Content-Length: %zu\r\n"
                          "Connection: close\r\n\r\n",
                          strlen(body));
    if (header_len <= 0 || (size_t)header_len >= sizeof(header) ||
        !admin_smoke_write_all(client, header, (size_t)header_len) ||
        !admin_smoke_write_all(client, body, strlen(body)))
    {
        close(client);
        return 0;
    }
    close(client);
    *request_valid = valid;
    return 1;
}

/*
 * Drain the merged stdout/stderr pipe while waiting with a monotonic deadline.
 * A timed-out process is terminated, and oversized output fails instead of
 * truncating diagnostics that could hide a trace leak.
 */
static int admin_smoke_collect(pid_t child,
                               int output_fd,
                               admin_smoke_result* result)
{
    uint64_t deadline =
        admin_smoke_now_ns() + ADMIN_SMOKE_PROCESS_TIMEOUT_NS;
    int child_status = 0;
    int child_done = 0;
    int failed = 0;
    int pipe_done = 0;
    int flags = 0;

    if (child <= 0 || output_fd < 0 || !result)
        return 0;
    flags = fcntl(output_fd, F_GETFL, 0);
    if (flags < 0 || fcntl(output_fd, F_SETFL, flags | O_NONBLOCK) != 0)
    {
        (void)kill(child, SIGKILL);
        while (waitpid(child, &child_status, 0) < 0 && errno == EINTR)
        {
        }
        return 0;
    }
    while ((!child_done || !pipe_done) &&
           admin_smoke_now_ns() < deadline)
    {
        struct pollfd wait_fd;
        pid_t waited = 0;

        memset(&wait_fd, 0, sizeof(wait_fd));
        wait_fd.fd = output_fd;
        wait_fd.events = POLLIN | POLLHUP;
        (void)poll(&wait_fd, 1u, 20);
        if (wait_fd.revents & (POLLIN | POLLHUP))
        {
            for (;;)
            {
                ssize_t count = 0;

                if (result->output_len + 1u >= sizeof(result->output))
                {
                    failed = 1;
                    break;
                }
                count = read(output_fd,
                             result->output + result->output_len,
                             sizeof(result->output) -
                                 result->output_len - 1u);
                if (count > 0)
                {
                    result->output_len += (size_t)count;
                    result->output[result->output_len] = '\0';
                    continue;
                }
                if (count == 0)
                    pipe_done = 1;
                else if (errno != EAGAIN && errno != EWOULDBLOCK &&
                         errno != EINTR)
                    failed = 1;
                break;
            }
        }
        if (failed)
            break;
        if (!child_done)
        {
            waited = waitpid(child, &child_status, WNOHANG);
            if (waited == child)
                child_done = 1;
            else if (waited < 0 && errno != EINTR)
            {
                failed = 1;
                break;
            }
        }
    }
    if (failed || !child_done)
    {
        (void)kill(child, SIGKILL);
        while (waitpid(child, &child_status, 0) < 0 && errno == EINTR)
        {
        }
        return 0;
    }
    if (!pipe_done)
    {
        ssize_t count = read(output_fd,
                             result->output + result->output_len,
                             sizeof(result->output) -
                                 result->output_len - 1u);

        if (count > 0)
        {
            result->output_len += (size_t)count;
            result->output[result->output_len] = '\0';
        }
    }
    if (!WIFEXITED(child_status))
        return 0;
    result->exit_code = WEXITSTATUS(child_status);
    return 1;
}

static int admin_smoke_spawn(const char* admin_path,
                             const char* endpoint,
                             admin_smoke_request_kind kind)
{
    const char* action = NULL;
    char* query_arguments[] = {
        (char*)admin_path,
        (char*)"--endpoint",
        (char*)endpoint,
        (char*)"--password-env",
        (char*)"LIBRDP_SMOKE_ADMIN_PASSWORD",
        (char*)"--timeout",
        (char*)"2000",
        (char*)"--no-window",
        NULL,
    };
    char* action_arguments[] = {
        (char*)admin_path,
        (char*)"--endpoint",
        (char*)endpoint,
        (char*)"--password-env",
        (char*)"LIBRDP_SMOKE_ADMIN_PASSWORD",
        (char*)"--timeout",
        (char*)"2000",
        (char*)"--action",
        NULL,
        (char*)"--session-id",
        (char*)"42",
        (char*)"--confirm",
        (char*)"--no-window",
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
    };

    if (!admin_path || !endpoint)
        return 0;
    if (kind == ADMIN_SMOKE_MESSAGE)
        action = "message";
    else if (kind == ADMIN_SMOKE_DISCONNECT)
        action = "disconnect";
    else if (kind == ADMIN_SMOKE_LOGOFF)
        action = "logoff";
    if (kind == ADMIN_SMOKE_QUERY)
        execv(admin_path, query_arguments);
    if (!action)
        return 0;
    action_arguments[8] = (char*)action;
    if (kind == ADMIN_SMOKE_MESSAGE)
    {
        action_arguments[13] = (char*)"--message-title";
        action_arguments[14] = (char*)"Smoke notice";
        action_arguments[15] = (char*)"--message-text";
        action_arguments[16] = (char*)"maintenance window";
    }
    execv(admin_path, action_arguments);
    return 0;
}

/*
 * Run one actual CLI invocation against one fixture exchange. The child gets
 * trace through environment configuration and a synthetic secret; the parent
 * verifies both network behavior and all merged process diagnostics.
 */
static int admin_smoke_exchange(const char* admin_path,
                                admin_smoke_request_kind kind,
                                admin_smoke_state* state,
                                admin_smoke_result* result)
{
    char endpoint[128];
    int endpoint_len = 0;
    int listen_fd = -1;
    int output_pipe[2] = {-1, -1};
    int served = 0;
    uint16_t port = 0u;
    pid_t child = -1;

    if (!admin_path || !state || !result)
        return 0;
    memset(result, 0, sizeof(*result));
    listen_fd = admin_smoke_listen(&port);
    if (listen_fd < 0)
        return 0;
    endpoint_len = snprintf(endpoint,
                            sizeof(endpoint),
                            "http://127.0.0.1:%u/wsman",
                            (unsigned int)port);
    if (endpoint_len <= 0 || (size_t)endpoint_len >= sizeof(endpoint) ||
        pipe(output_pipe) != 0)
    {
        close(listen_fd);
        return 0;
    }
    child = fork();
    if (child < 0)
    {
        close(output_pipe[0]);
        close(output_pipe[1]);
        close(listen_fd);
        return 0;
    }
    if (child == 0)
    {
        close(output_pipe[0]);
        close(listen_fd);
        if (dup2(output_pipe[1], STDOUT_FILENO) < 0 ||
            dup2(output_pipe[1], STDERR_FILENO) < 0)
            _exit(126);
        close(output_pipe[1]);
        (void)setenv("LIBRDP_SMOKE_ADMIN_PASSWORD",
                     "synthetic-admin-secret",
                     1);
        (void)setenv("LIBRDP_TRACE_CLIENT", "1", 1);
        (void)setenv("LIBRDP_TRACE_LEVEL", "debug", 1);
        if (!admin_smoke_spawn(admin_path,
                               endpoint,
                               kind))
            _exit(127);
        _exit(127);
    }
    close(output_pipe[1]);
    served = admin_smoke_serve(listen_fd,
                               kind,
                               state,
                               &result->request_valid);
    close(listen_fd);
    if (!served)
        (void)kill(child, SIGKILL);
    if (!admin_smoke_collect(child, output_pipe[0], result))
        served = 0;
    close(output_pipe[0]);
    return served;
}

static int admin_smoke_output_clean(const admin_smoke_result* result)
{
    return result &&
           strstr(result->output, "synthetic-admin-secret") == NULL &&
           strstr(result->output, "AddressSanitizer") == NULL &&
           strstr(result->output, "runtime error:") == NULL;
}

static void admin_smoke_report(const admin_smoke_result* result)
{
    if (result && result->output_len > 0u)
        fputs(result->output, stdout);
}

static int admin_smoke_inventory(const char* admin_path)
{
    admin_smoke_state state = {1, 1, 0u};
    admin_smoke_result result;

    if (!admin_smoke_exchange(admin_path,
                              ADMIN_SMOKE_QUERY,
                              &state,
                              &result) ||
        !result.request_valid || result.exit_code != 0 ||
        !admin_smoke_output_clean(&result) ||
        !strstr(result.output, "client.admin.query.done") ||
        !strstr(result.output, "sessions count=1") ||
        !strstr(result.output, "session_id=42") ||
        !strstr(result.output, "logon_id=42001") ||
        !strstr(result.output, "user=\"smoke-user\"") ||
        !strstr(result.output, "domain=\"SMOKE-DOMAIN\"") ||
        !strstr(result.output, "state=\"Active\"") ||
        !strstr(result.output, "client=\"smoke-client\"") ||
        !strstr(result.output, "station=\"rdp-tcp#smoke\"") ||
        !strstr(result.output, "protocol=\"rdp\""))
    {
        fputs(result.output, stderr);
        return 1;
    }
    admin_smoke_report(&result);
    return 0;
}

static int admin_smoke_query_state(const char* admin_path,
                                   admin_smoke_state* state,
                                   const char* expected)
{
    admin_smoke_result result;

    if (!admin_smoke_exchange(admin_path,
                              ADMIN_SMOKE_QUERY,
                              state,
                              &result) ||
        !result.request_valid || result.exit_code != 0 ||
        !admin_smoke_output_clean(&result) ||
        !strstr(result.output, expected))
    {
        fputs(result.output, stderr);
        return 0;
    }
    admin_smoke_report(&result);
    return 1;
}

static int admin_smoke_action(const char* admin_path,
                              admin_smoke_request_kind kind,
                              admin_smoke_state* state,
                              const char* expected_type)
{
    admin_smoke_result result;

    if (!admin_smoke_exchange(admin_path, kind, state, &result) ||
        !result.request_valid || result.exit_code != 0 ||
        !admin_smoke_output_clean(&result) ||
        !strstr(result.output, "client.admin.action.done") ||
        !strstr(result.output, expected_type) ||
        strstr(result.output, "maintenance window"))
    {
        fputs(result.output, stderr);
        return 0;
    }
    admin_smoke_report(&result);
    return 1;
}

static int admin_smoke_actions(const char* admin_path)
{
    admin_smoke_state state = {1, 1, 0u};

    if (!admin_smoke_action(admin_path,
                            ADMIN_SMOKE_MESSAGE,
                            &state,
                            "admin action done type=3 session_id=42") ||
        state.messages != 1u || !state.connected || !state.logged_on ||
        !admin_smoke_query_state(admin_path, &state, "state=\"Active\"") ||
        !admin_smoke_action(admin_path,
                            ADMIN_SMOKE_DISCONNECT,
                            &state,
                            "admin action done type=2 session_id=42") ||
        state.connected || !state.logged_on ||
        !admin_smoke_query_state(admin_path,
                                 &state,
                                 "state=\"Disconnected\"") ||
        !admin_smoke_action(admin_path,
                            ADMIN_SMOKE_LOGOFF,
                            &state,
                            "admin action done type=1 session_id=42") ||
        state.connected || state.logged_on ||
        !admin_smoke_query_state(admin_path, &state, "sessions count=0"))
        return 1;
    return 0;
}

int main(int argc, char** argv)
{
    if (argc != 3)
        return 2;
    if (strcmp(argv[1], "inventory") == 0)
        return admin_smoke_inventory(argv[2]);
    if (strcmp(argv[1], "actions") == 0)
        return admin_smoke_actions(argv[2]);
    return 2;
}
