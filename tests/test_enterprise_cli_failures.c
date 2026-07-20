/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: workspace and administration failure-path smoke tests.
 * Coverage: the real headless applications process TLS transport failure,
 * authentication rejection, malformed XML, empty and ambiguous feeds, and a
 * timed-out administrative action.
 * Bug classes: accidental success after transport failure, ambiguous resource
 * launch, stalled actions, malformed response acceptance, and trace leaks.
 * Determinism: each process talks to one bounded loopback fixture and all
 * credentials, identities, resources, and action text are synthetic.
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

#define ENTERPRISE_SMOKE_IO_TIMEOUT_MS 5000
#define ENTERPRISE_SMOKE_PROCESS_TIMEOUT_NS 10000000000ULL
#define ENTERPRISE_SMOKE_REQUEST_CAPACITY 16384u
#define ENTERPRISE_SMOKE_OUTPUT_CAPACITY 32768u

typedef enum enterprise_smoke_application
{
    ENTERPRISE_SMOKE_WORKSPACE,
    ENTERPRISE_SMOKE_ADMIN
} enterprise_smoke_application;

typedef enum enterprise_smoke_response
{
    ENTERPRISE_SMOKE_TLS_CLOSE,
    ENTERPRISE_SMOKE_AUTH_REJECT,
    ENTERPRISE_SMOKE_MALFORMED_XML,
    ENTERPRISE_SMOKE_EMPTY_FEED,
    ENTERPRISE_SMOKE_DUPLICATE_FEED,
    ENTERPRISE_SMOKE_ACTION_TIMEOUT
} enterprise_smoke_response;

typedef struct enterprise_smoke_case
{
    const char* name;
    enterprise_smoke_application application;
    enterprise_smoke_response response;
    int expected_exit;
    const char* expected_event;
    const char* expected_message;
} enterprise_smoke_case;

typedef struct enterprise_smoke_result
{
    char output[ENTERPRISE_SMOKE_OUTPUT_CAPACITY];
    size_t output_len;
    int exit_code;
    int request_valid;
} enterprise_smoke_result;

static const enterprise_smoke_case enterprise_smoke_cases[] = {
    {
      "workspace-tls",
      ENTERPRISE_SMOKE_WORKSPACE,
      ENTERPRISE_SMOKE_TLS_CLOSE,
      3,
      "client.workspace.fetch.failed",
      "workspace fetch failed:",
    },
    {
      "admin-tls",
      ENTERPRISE_SMOKE_ADMIN,
      ENTERPRISE_SMOKE_TLS_CLOSE,
      3,
      "client.admin.query.failed",
      "admin query failed:",
    },
    {
      "workspace-auth",
      ENTERPRISE_SMOKE_WORKSPACE,
      ENTERPRISE_SMOKE_AUTH_REJECT,
      3,
      "client.workspace.fetch.failed",
      "workspace fetch failed: io_error",
    },
    {
      "admin-auth",
      ENTERPRISE_SMOKE_ADMIN,
      ENTERPRISE_SMOKE_AUTH_REJECT,
      3,
      "client.admin.query.failed",
      "admin query failed: io_error",
    },
    {
      "workspace-malformed",
      ENTERPRISE_SMOKE_WORKSPACE,
      ENTERPRISE_SMOKE_MALFORMED_XML,
      3,
      "client.workspace.fetch.failed",
      "workspace fetch failed: protocol_error",
    },
    {
      "admin-malformed",
      ENTERPRISE_SMOKE_ADMIN,
      ENTERPRISE_SMOKE_MALFORMED_XML,
      3,
      "client.admin.query.failed",
      "admin query failed: protocol_error",
    },
    {
      "workspace-empty",
      ENTERPRISE_SMOKE_WORKSPACE,
      ENTERPRISE_SMOKE_EMPTY_FEED,
      0,
      "client.workspace.fetch.done",
      "resources count=0",
    },
    {
      "workspace-duplicate",
      ENTERPRISE_SMOKE_WORKSPACE,
      ENTERPRISE_SMOKE_DUPLICATE_FEED,
      4,
      "client.workspace.fetch.done",
      "selected resource is ambiguous",
    },
    {
      "admin-action-timeout",
      ENTERPRISE_SMOKE_ADMIN,
      ENTERPRISE_SMOKE_ACTION_TIMEOUT,
      3,
      "client.admin.action.failed",
      "admin action failed: timeout",
    },
};

static uint64_t enterprise_smoke_now_ns(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0u;
    return (uint64_t)now.tv_sec * 1000000000ULL +
           (uint64_t)now.tv_nsec;
}

static int enterprise_smoke_write_all(int fd,
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

static int enterprise_smoke_listen(uint16_t* port)
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

static int enterprise_smoke_content_length(const char* request,
                                           size_t header_len,
                                           size_t* content_len,
                                           int* present)
{
    static const char field[] = "Content-Length:";
    const char* cursor = request;
    const char* header_end = request + header_len;

    if (!request || !content_len || !present)
        return 0;
    *content_len = 0u;
    *present = 0;
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
                end != line_end ||
                parsed > ENTERPRISE_SMOKE_REQUEST_CAPACITY)
                return 0;
            *content_len = (size_t)parsed;
            *present = 1;
            return 1;
        }
        cursor = line_end + 2;
    }
    return 1;
}

/*
 * Read one HTTP request, including a POST body when Content-Length is present.
 * Every read is bounded by poll so a malformed or partial client cannot stall
 * the smoke fixture.
 */
static int enterprise_smoke_read_http(int client,
                                      char* request,
                                      size_t request_capacity)
{
    char* headers_end = NULL;
    size_t content_len = 0u;
    size_t expected = 0u;
    size_t used = 0u;
    int content_length_present = 0;

    if (client < 0 || !request || request_capacity < 2u)
        return 0;
    for (;;)
    {
        struct pollfd wait_fd;
        ssize_t count = 0;

        memset(&wait_fd, 0, sizeof(wait_fd));
        wait_fd.fd = client;
        wait_fd.events = POLLIN;
        if (poll(&wait_fd, 1u, ENTERPRISE_SMOKE_IO_TIMEOUT_MS) != 1)
            return 0;
        if (used + 1u >= request_capacity)
            return 0;
        count = read(client,
                     request + used,
                     request_capacity - used - 1u);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return 0;
        used += (size_t)count;
        request[used] = '\0';
        headers_end = strstr(request, "\r\n\r\n");
        if (headers_end && expected == 0u)
        {
            size_t header_len =
                (size_t)(headers_end - request) + 4u;

            if (!enterprise_smoke_content_length(
                  request,
                  header_len,
                  &content_len,
                  &content_length_present) ||
                content_len > request_capacity - header_len - 1u)
                return 0;
            expected = header_len +
                       (content_length_present ? content_len : 0u);
        }
        if (expected > 0u && used >= expected)
            return used == expected;
    }
}

static int enterprise_smoke_accept(int listen_fd)
{
    struct pollfd wait_fd;

    if (listen_fd < 0)
        return -1;
    memset(&wait_fd, 0, sizeof(wait_fd));
    wait_fd.fd = listen_fd;
    wait_fd.events = POLLIN;
    if (poll(&wait_fd, 1u, ENTERPRISE_SMOKE_IO_TIMEOUT_MS) != 1)
        return -1;
    return accept(listen_fd, NULL, NULL);
}

static int enterprise_smoke_request_valid(
    enterprise_smoke_application application,
    enterprise_smoke_response response,
    const char* request)
{
    if (!request)
        return 0;
    if (application == ENTERPRISE_SMOKE_WORKSPACE)
        return strstr(request, "GET /feed HTTP/") != NULL;
    if (!strstr(request, "POST /wsman HTTP/") ||
        !strstr(request, "</s:Envelope>"))
        return 0;
    if (response == ENTERPRISE_SMOKE_ACTION_TIMEOUT)
    {
        return strstr(request, "Win32_Process/Create") != NULL &&
               strstr(request,
                      "Smoke timeout title: Smoke timeout body") != NULL;
    }
    return strstr(request, "<n:Enumerate/>") != NULL;
}

static const char* enterprise_smoke_body(
    enterprise_smoke_application application,
    enterprise_smoke_response response)
{
    if (response == ENTERPRISE_SMOKE_MALFORMED_XML)
    {
        return application == ENTERPRISE_SMOKE_WORKSPACE ?
                 "<Workspace><Resources><Resource>" :
                 "<s:Envelope><s:Body><Session>";
    }
    if (response == ENTERPRISE_SMOKE_EMPTY_FEED)
        return "<Workspace><Resources/></Workspace>";
    if (response == ENTERPRISE_SMOKE_DUPLICATE_FEED)
    {
        return
          "<Workspace><Resources>"
          "<Resource><ID>shared-resource</ID><Title>First</Title>"
          "<Type>Desktop</Type><TerminalServer>first.example.test</TerminalServer>"
          "</Resource>"
          "<Resource><ID>shared-resource</ID><Title>Second</Title>"
          "<Type>Desktop</Type><TerminalServer>second.example.test</TerminalServer>"
          "</Resource>"
          "</Resources></Workspace>";
    }
    return "";
}

/*
 * Serve the single exchange required by a case. TLS cases deliberately close
 * after receiving a ClientHello, authentication cases return an explicit 401,
 * and timeout cases retain the accepted request beyond the client deadline.
 */
static int enterprise_smoke_serve(
    int listen_fd,
    const enterprise_smoke_case* test_case,
    int* request_valid)
{
    char header[512];
    char request[ENTERPRISE_SMOKE_REQUEST_CAPACITY];
    const char* body = NULL;
    const char* status = "200 OK";
    const char* auth = "";
    int client = -1;
    int header_len = 0;
    int result = 0;

    if (!test_case || !request_valid)
        return 0;
    *request_valid = 0;
    client = enterprise_smoke_accept(listen_fd);
    if (client < 0)
        return 0;
    if (test_case->response == ENTERPRISE_SMOKE_TLS_CLOSE)
    {
        struct pollfd wait_fd;
        uint8_t hello[4096];
        ssize_t count = 0;

        memset(&wait_fd, 0, sizeof(wait_fd));
        wait_fd.fd = client;
        wait_fd.events = POLLIN;
        if (poll(&wait_fd, 1u, ENTERPRISE_SMOKE_IO_TIMEOUT_MS) == 1)
            count = read(client, hello, sizeof(hello));
        *request_valid =
            count > 0 && hello[0] == 0x16u;
        close(client);
        return *request_valid;
    }
    if (!enterprise_smoke_read_http(client,
                                    request,
                                    sizeof(request)))
    {
        close(client);
        return 0;
    }
    *request_valid =
        enterprise_smoke_request_valid(test_case->application,
                                       test_case->response,
                                       request);
    if (test_case->response == ENTERPRISE_SMOKE_ACTION_TIMEOUT)
    {
        const struct timespec delay = {0, 500000000L};

        (void)nanosleep(&delay, NULL);
        close(client);
        return *request_valid;
    }
    body = enterprise_smoke_body(test_case->application,
                                 test_case->response);
    if (test_case->response == ENTERPRISE_SMOKE_AUTH_REJECT)
    {
        status = "401 Unauthorized";
        auth =
          "WWW-Authenticate: Basic realm=\"enterprise-smoke\"\r\n";
    }
    header_len = snprintf(
      header,
      sizeof(header),
      "HTTP/1.1 %s\r\n"
      "Content-Type: application/xml\r\n"
      "%s"
      "Content-Length: %zu\r\n"
      "Connection: close\r\n\r\n",
      status,
      auth,
      strlen(body));
    if (header_len > 0 &&
        (size_t)header_len < sizeof(header) &&
        enterprise_smoke_write_all(client,
                                   header,
                                   (size_t)header_len) &&
        enterprise_smoke_write_all(client, body, strlen(body)))
        result = 1;
    close(client);
    return result && *request_valid;
}

/*
 * Drain merged child diagnostics without allowing output growth or a hung
 * process to obscure the actual application failure.
 */
static int enterprise_smoke_collect(pid_t child,
                                    int output_fd,
                                    enterprise_smoke_result* result)
{
    uint64_t deadline =
        enterprise_smoke_now_ns() +
        ENTERPRISE_SMOKE_PROCESS_TIMEOUT_NS;
    int child_status = 0;
    int child_done = 0;
    int pipe_done = 0;
    int failed = 0;
    int flags = 0;

    if (child <= 0 || output_fd < 0 || !result)
        return 0;
    flags = fcntl(output_fd, F_GETFL, 0);
    if (flags < 0 ||
        fcntl(output_fd, F_SETFL, flags | O_NONBLOCK) != 0)
        failed = 1;
    while (!failed &&
           (!child_done || !pipe_done) &&
           enterprise_smoke_now_ns() < deadline)
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

                if (result->output_len + 1u >=
                    sizeof(result->output))
                {
                    failed = 1;
                    break;
                }
                count = read(
                  output_fd,
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
                else if (errno != EAGAIN &&
                         errno != EWOULDBLOCK &&
                         errno != EINTR)
                    failed = 1;
                break;
            }
        }
        if (!child_done)
        {
            waited = waitpid(child, &child_status, WNOHANG);
            if (waited == child)
                child_done = 1;
            else if (waited < 0 && errno != EINTR)
                failed = 1;
        }
    }
    if (failed || !child_done)
    {
        (void)kill(child, SIGKILL);
        while (waitpid(child, &child_status, 0) < 0 &&
               errno == EINTR)
        {
        }
        return 0;
    }
    if (!WIFEXITED(child_status))
        return 0;
    result->exit_code = WEXITSTATUS(child_status);
    return 1;
}

static void enterprise_smoke_exec(
    const enterprise_smoke_case* test_case,
    const char* workspace_path,
    const char* admin_path,
    const char* endpoint)
{
    char* arguments[24];
    size_t count = 0u;

    if (!test_case || !workspace_path || !admin_path || !endpoint)
        _exit(126);
    arguments[count++] =
      (char*)(test_case->application == ENTERPRISE_SMOKE_WORKSPACE ?
                workspace_path :
                admin_path);
    arguments[count++] =
      (char*)(test_case->application == ENTERPRISE_SMOKE_WORKSPACE ?
                "--feed" :
                "--endpoint");
    arguments[count++] = (char*)endpoint;
    arguments[count++] = (char*)"--user";
    arguments[count++] = (char*)"enterprise-smoke-user";
    arguments[count++] = (char*)"--password-env";
    arguments[count++] =
      (char*)"LIBRDP_SMOKE_ENTERPRISE_PASSWORD";
    arguments[count++] = (char*)"--domain";
    arguments[count++] = (char*)"ENTERPRISE-SMOKE-DOMAIN";
    arguments[count++] = (char*)"--timeout";
    arguments[count++] =
      (char*)(test_case->response == ENTERPRISE_SMOKE_ACTION_TIMEOUT ?
                "100" :
                "1500");
    if (test_case->response == ENTERPRISE_SMOKE_DUPLICATE_FEED)
    {
        arguments[count++] = (char*)"--select";
        arguments[count++] = (char*)"shared-resource";
        arguments[count++] = (char*)"--viewer";
        arguments[count++] =
          (char*)"/nonexistent/enterprise-smoke-viewer";
        arguments[count++] = (char*)"--launch";
    }
    if (test_case->response == ENTERPRISE_SMOKE_ACTION_TIMEOUT)
    {
        arguments[count++] = (char*)"--action";
        arguments[count++] = (char*)"message";
        arguments[count++] = (char*)"--session-id";
        arguments[count++] = (char*)"42";
        arguments[count++] = (char*)"--message-title";
        arguments[count++] = (char*)"Smoke timeout title";
        arguments[count++] = (char*)"--message-text";
        arguments[count++] = (char*)"Smoke timeout body";
    }
    arguments[count++] = (char*)"--no-window";
    arguments[count] = NULL;
    execv(arguments[0], arguments);
    _exit(127);
}

static int enterprise_smoke_output_clean(
    const enterprise_smoke_result* result)
{
    return result &&
           strstr(result->output,
                  "enterprise-smoke-secret") == NULL &&
           strstr(result->output,
                  "enterprise-smoke-user") == NULL &&
           strstr(result->output,
                  "ENTERPRISE-SMOKE-DOMAIN") == NULL &&
           strstr(result->output,
                  "Smoke timeout title") == NULL &&
           strstr(result->output,
                  "Smoke timeout body") == NULL &&
           strstr(result->output, "AddressSanitizer") == NULL &&
           strstr(result->output, "runtime error:") == NULL;
}

static int enterprise_smoke_validate(
    const enterprise_smoke_case* test_case,
    const enterprise_smoke_result* result)
{
    if (!test_case || !result ||
        !result->request_valid ||
        result->exit_code != test_case->expected_exit ||
        !enterprise_smoke_output_clean(result) ||
        !strstr(result->output, test_case->expected_event) ||
        !strstr(result->output, test_case->expected_message))
        return 0;
    if (test_case->response == ENTERPRISE_SMOKE_DUPLICATE_FEED)
    {
        return strstr(result->output, "resources count=2") != NULL &&
               strstr(result->output, "execvp") == NULL;
    }
    if (test_case->response == ENTERPRISE_SMOKE_EMPTY_FEED)
        return strstr(result->output, "resources=0") != NULL;
    if (test_case->response == ENTERPRISE_SMOKE_ACTION_TIMEOUT)
        return strstr(result->output, "status=timeout") != NULL;
    return 1;
}

/*
 * Fork one actual application and service its loopback endpoint in the parent.
 * The parent owns all fixture descriptors and validates the full trace before
 * reporting the case as successful.
 */
static int enterprise_smoke_run(
    const enterprise_smoke_case* test_case,
    const char* workspace_path,
    const char* admin_path)
{
    enterprise_smoke_result result;
    char endpoint[128];
    const char* scheme = NULL;
    const char* path = NULL;
    int endpoint_len = 0;
    int listen_fd = -1;
    int output_pipe[2] = {-1, -1};
    int served = 0;
    uint16_t port = 0u;
    pid_t child = -1;

    if (!test_case || !workspace_path || !admin_path)
        return 0;
    memset(&result, 0, sizeof(result));
    listen_fd = enterprise_smoke_listen(&port);
    if (listen_fd < 0)
        return 0;
    scheme =
      test_case->response == ENTERPRISE_SMOKE_TLS_CLOSE ?
        "https" :
        "http";
    path =
      test_case->application == ENTERPRISE_SMOKE_WORKSPACE ?
        "feed" :
        "wsman";
    endpoint_len = snprintf(endpoint,
                            sizeof(endpoint),
                            "%s://127.0.0.1:%u/%s",
                            scheme,
                            (unsigned int)port,
                            path);
    if (endpoint_len <= 0 ||
        (size_t)endpoint_len >= sizeof(endpoint) ||
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
        (void)setenv("LIBRDP_SMOKE_ENTERPRISE_PASSWORD",
                     "enterprise-smoke-secret",
                     1);
        (void)setenv("LIBRDP_TRACE_CLIENT", "1", 1);
        (void)setenv("LIBRDP_TRACE_LEVEL", "debug", 1);
        (void)setenv("NO_PROXY", "127.0.0.1", 1);
        (void)setenv("no_proxy", "127.0.0.1", 1);
        (void)unsetenv("HTTP_PROXY");
        (void)unsetenv("HTTPS_PROXY");
        (void)unsetenv("http_proxy");
        (void)unsetenv("https_proxy");
        enterprise_smoke_exec(test_case,
                              workspace_path,
                              admin_path,
                              endpoint);
    }
    close(output_pipe[1]);
    served = enterprise_smoke_serve(listen_fd,
                                    test_case,
                                    &result.request_valid);
    close(listen_fd);
    if (!served)
        (void)kill(child, SIGKILL);
    if (!enterprise_smoke_collect(child,
                                  output_pipe[0],
                                  &result))
        served = 0;
    close(output_pipe[0]);
    if (!served ||
        !enterprise_smoke_validate(test_case, &result))
    {
        fprintf(stderr,
                "enterprise smoke failed: %s exit=%d request=%d\n",
                test_case->name,
                result.exit_code,
                result.request_valid);
        fputs(result.output, stderr);
        return 0;
    }
    fputs(result.output, stdout);
    return 1;
}

static const enterprise_smoke_case* enterprise_smoke_find(
    const char* name)
{
    size_t index = 0u;

    if (!name)
        return NULL;
    for (index = 0u;
         index < sizeof(enterprise_smoke_cases) /
                   sizeof(enterprise_smoke_cases[0]);
         index++)
    {
        if (strcmp(name, enterprise_smoke_cases[index].name) == 0)
            return &enterprise_smoke_cases[index];
    }
    return NULL;
}

int main(int argc, char** argv)
{
    const enterprise_smoke_case* test_case = NULL;

    (void)signal(SIGPIPE, SIG_IGN);
    if (argc != 4)
        return 2;
    test_case = enterprise_smoke_find(argv[1]);
    if (!test_case)
        return 2;
    return enterprise_smoke_run(test_case, argv[2], argv[3]) ?
             0 :
             1;
}
