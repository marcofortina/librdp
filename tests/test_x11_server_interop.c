/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
/*
 * Module: opt-in X11 server interoperability smoke.
 * Coverage: negotiated desktop geometry, activation, framebuffer delivery and
 * client-drive traversal through an independently implemented RDP client.
 * Bug classes: activation ordering, capture-size mismatches, channel startup
 * races, stalled child processes and incomplete drive request correlation.
 * Determinism: the test uses isolated Xvfb displays and synthetic credentials;
 * it is skipped unless an external client executable is supplied by environment.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define INTEROP_SKIP_RETURN_CODE 77
#define INTEROP_WAIT_STEP_MS 50u
#define INTEROP_STARTUP_STEPS 200u
#define INTEROP_SESSION_STEPS 300u

typedef struct interop_processes
{
    pid_t server_display;
    pid_t client_display;
    pid_t server;
    pid_t client;
    pid_t drive_reader;
} interop_processes;

static void interop_sleep_ms(unsigned int milliseconds)
{
    struct timespec request;

    request.tv_sec = (time_t)(milliseconds / 1000u);
    request.tv_nsec = (long)(milliseconds % 1000u) * 1000000L;
    while (nanosleep(&request, &request) != 0 && errno == EINTR)
    {
    }
}

static int interop_process_alive(pid_t process)
{
    if (process <= 0)
        return 0;
    return kill(process, 0) == 0 || errno == EPERM;
}

static void interop_stop_process(pid_t* process)
{
    unsigned int attempt = 0u;
    int status = 0;

    if (!process || *process <= 0)
        return;
    if (kill(*process, SIGTERM) != 0 && errno != ESRCH)
        return;
    for (attempt = 0u; attempt < 20u; attempt++)
    {
        pid_t waited = waitpid(*process, &status, WNOHANG);

        if (waited == *process || (waited < 0 && errno == ECHILD))
        {
            *process = -1;
            return;
        }
        interop_sleep_ms(INTEROP_WAIT_STEP_MS);
    }
    (void)kill(*process, SIGKILL);
    (void)waitpid(*process, &status, 0);
    *process = -1;
}

static int interop_file_contains(const char* path, const char* needle)
{
    FILE* file = NULL;
    char buffer[4096];
    size_t needle_len = 0u;
    size_t overlap = 0u;
    int found = 0;

    if (!path || !needle || needle[0] == '\0')
        return 0;
    file = fopen(path, "rb");
    if (!file)
        return 0;
    needle_len = strlen(needle);
    while (!found)
    {
        size_t count = fread(buffer + overlap,
                             1u,
                             sizeof(buffer) - overlap,
                             file);
        size_t used = overlap + count;

        if (used >= needle_len)
        {
            size_t index = 0u;

            for (index = 0u; index <= used - needle_len; index++)
            {
                if (memcmp(buffer + index, needle, needle_len) == 0)
                {
                    found = 1;
                    break;
                }
            }
        }
        if (found || count == 0u)
            break;
        overlap = needle_len > 1u && used >= needle_len - 1u
                      ? needle_len - 1u
                      : used;
        if (overlap > 0u)
            memmove(buffer, buffer + used - overlap, overlap);
    }
    fclose(file);
    return found;
}

static void interop_dump_file(const char* label, const char* path)
{
    FILE* file = NULL;
    char buffer[4096];
    size_t count = 0u;

    fprintf(stderr, "--- %s ---\n", label);
    file = fopen(path, "rb");
    if (!file)
    {
        fprintf(stderr, "unavailable: %s\n", strerror(errno));
        return;
    }
    while ((count = fread(buffer, 1u, sizeof(buffer), file)) > 0u)
        (void)fwrite(buffer, 1u, count, stderr);
    fclose(file);
}

static int interop_open_log(const char* path)
{
    return open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
}

static pid_t interop_start_xvfb(const char* display, const char* log_path)
{
    pid_t child = fork();

    if (child != 0)
        return child;
    {
        int log = interop_open_log(log_path);

        if (log < 0 || dup2(log, STDOUT_FILENO) < 0 ||
            dup2(log, STDERR_FILENO) < 0)
            _exit(126);
        if (log > STDERR_FILENO)
            close(log);
    }
    execl(LIBRDP_TEST_XVFB_PATH,
          LIBRDP_TEST_XVFB_PATH,
          display,
          "-screen",
          "0",
          "1024x768x24",
          "-nolisten",
          "tcp",
          "-ac",
          (char*)NULL);
    _exit(127);
}

static int interop_wait_for_display(const char* display, pid_t process)
{
    char socket_path[PATH_MAX];
    int length = 0;
    unsigned int attempt = 0u;

    if (!display || display[0] != ':')
        return 0;
    length = snprintf(socket_path,
                      sizeof(socket_path),
                      "/tmp/.X11-unix/X%s",
                      display + 1);
    if (length <= 0 || (size_t)length >= sizeof(socket_path))
        return 0;
    for (attempt = 0u; attempt < INTEROP_STARTUP_STEPS; attempt++)
    {
        if (access(socket_path, F_OK) == 0)
            return 1;
        if (!interop_process_alive(process))
            return 0;
        interop_sleep_ms(INTEROP_WAIT_STEP_MS);
    }
    return 0;
}

static int interop_select_displays(char server[32], char client[32])
{
    unsigned int attempt = 0u;

    for (attempt = 0u; attempt < 100u; attempt++)
    {
        unsigned int number =
            300u + ((unsigned int)getpid() + attempt * 2u) % 500u;
        char first_socket[PATH_MAX];
        char second_socket[PATH_MAX];
        int first_length = 0;
        int second_length = 0;

        first_length = snprintf(first_socket,
                                sizeof(first_socket),
                                "/tmp/.X11-unix/X%u",
                                number);
        second_length = snprintf(second_socket,
                                 sizeof(second_socket),
                                 "/tmp/.X11-unix/X%u",
                                 number + 1u);
        if (first_length <= 0 || second_length <= 0 ||
            (size_t)first_length >= sizeof(first_socket) ||
            (size_t)second_length >= sizeof(second_socket))
            return 0;
        if (access(first_socket, F_OK) == 0 ||
            access(second_socket, F_OK) == 0)
            continue;
        if (snprintf(server, 32u, ":%u", number) <= 0 ||
            snprintf(client, 32u, ":%u", number + 1u) <= 0)
            return 0;
        return 1;
    }
    return 0;
}

static uint16_t interop_select_port(void)
{
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    int socket_fd = -1;
    uint16_t port = 0u;

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0)
        return 0u;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1)
    {
        close(socket_fd);
        return 0u;
    }
    if (bind(socket_fd,
             (const struct sockaddr*)&address,
             sizeof(address)) == 0 &&
        getsockname(socket_fd,
                    (struct sockaddr*)&address,
                    &address_len) == 0)
        port = ntohs(address.sin_port);
    close(socket_fd);
    return port;
}

static pid_t interop_start_server(const char* display,
                                  uint16_t port,
                                  const char* mount_path,
                                  const char* log_path)
{
    char port_text[16];
    pid_t child = 0;

    if (snprintf(port_text,
                 sizeof(port_text),
                 "%u",
                 (unsigned int)port) <= 0)
        return -1;
    child = fork();
    if (child != 0)
        return child;
    {
        int log = interop_open_log(log_path);

        if (log < 0 || dup2(log, STDOUT_FILENO) < 0 ||
            dup2(log, STDERR_FILENO) < 0)
            _exit(126);
        if (log > STDERR_FILENO)
            close(log);
    }
    if (setenv("DISPLAY", display, 1) != 0 ||
        setenv("LIBRDP_TRACE_PROTOCOL", "1", 1) != 0 ||
        setenv("LIBRDP_TRACE_CLIENT", "1", 1) != 0 ||
        setenv("LIBRDP_TRACE_LEVEL", "debug", 1) != 0 ||
        setenv("LIBRDP_TRACE_HEX_BYTES", "96", 1) != 0)
        _exit(126);
    execl(LIBRDP_TEST_X11_SERVER_PATH,
          LIBRDP_TEST_X11_SERVER_PATH,
          "--display",
          display,
          "--bind",
          "127.0.0.1",
          "--port",
          port_text,
          "--security",
          "standard",
          "--allow-standard-security",
          "--allow-capture",
          "--allow-input",
          "--allow-clipboard",
          "--allow-drive",
          "--drive-mount",
          mount_path,
          "--max-peers",
          "1",
          "--max-fps",
          "30",
          (char*)NULL);
    _exit(127);
}

static pid_t interop_start_client(const char* executable,
                                  const char* display,
                                  uint16_t port,
                                  const char* drive_path,
                                  const char* log_path)
{
    char endpoint[64];
    char drive[PATH_MAX + 32u];
    char* arguments[13];
    int endpoint_length = 0;
    int drive_length = 0;
    pid_t child = 0;

    endpoint_length = snprintf(endpoint,
                               sizeof(endpoint),
                               "/v:127.0.0.1:%u",
                               (unsigned int)port);
    drive_length = snprintf(drive,
                            sizeof(drive),
                            "/drive:SMOKE,%s",
                            drive_path);
    if (endpoint_length <= 0 ||
        (size_t)endpoint_length >= sizeof(endpoint) ||
        drive_length <= 0 || (size_t)drive_length >= sizeof(drive))
        return -1;
    arguments[0] = (char*)executable;
    arguments[1] = endpoint;
    arguments[2] = "/u:interop-user";
    arguments[3] = "/p:interop-secret";
    arguments[4] = "/sec:rdp";
    arguments[5] = "/cert:ignore";
    arguments[6] = "/size:640x480";
    arguments[7] = drive;
    arguments[8] = "/gfx:off";
    arguments[9] = "/network:lan";
    arguments[10] = "/audio-mode:2";
    arguments[11] = "/log-level:INFO";
    arguments[12] = NULL;
    child = fork();
    if (child != 0)
        return child;
    {
        int log = interop_open_log(log_path);

        if (log < 0 || dup2(log, STDOUT_FILENO) < 0 ||
            dup2(log, STDERR_FILENO) < 0)
            _exit(126);
        if (log > STDERR_FILENO)
            close(log);
    }
    if (setenv("DISPLAY", display, 1) != 0)
        _exit(126);
    execv(executable, arguments);
    _exit(127);
}

static pid_t interop_start_drive_reader(const char* mount_path)
{
    static const char expected[] = "synthetic drive marker\n";
    char path[PATH_MAX];
    int length = 0;
    pid_t child = 0;

    length = snprintf(path,
                      sizeof(path),
                      "%s/peer-1-1/SMOKE/marker.txt",
                      mount_path);
    if (length <= 0 || (size_t)length >= sizeof(path))
        return -1;
    child = fork();
    if (child != 0)
        return child;
    {
        unsigned int attempt = 0u;

        for (attempt = 0u; attempt < INTEROP_SESSION_STEPS; attempt++)
        {
            int file = open(path, O_RDONLY);

            if (file >= 0)
            {
                char contents[sizeof(expected)];
                ssize_t count = read(file, contents, sizeof(contents));

                close(file);
                if (count == (ssize_t)(sizeof(expected) - 1u) &&
                    memcmp(contents, expected, sizeof(expected) - 1u) == 0)
                    _exit(0);
                _exit(2);
            }
            interop_sleep_ms(INTEROP_WAIT_STEP_MS);
        }
    }
    _exit(3);
}

static int interop_wait_child_success(pid_t* process,
                                      pid_t required_peer,
                                      unsigned int attempts)
{
    unsigned int attempt = 0u;

    if (!process || *process <= 0)
        return 0;
    for (attempt = 0u; attempt < attempts; attempt++)
    {
        int status = 0;
        pid_t waited = waitpid(*process, &status, WNOHANG);

        if (waited == *process)
        {
            *process = -1;
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        }
        if (waited < 0)
            return 0;
        if (!interop_process_alive(required_peer))
            return 0;
        interop_sleep_ms(INTEROP_WAIT_STEP_MS);
    }
    return 0;
}

static int interop_wait_server_ready(const char* log_path, pid_t server)
{
    unsigned int attempt = 0u;

    for (attempt = 0u; attempt < INTEROP_STARTUP_STEPS; attempt++)
    {
        if (interop_file_contains(log_path, "state=listening port="))
            return 1;
        if (!interop_process_alive(server))
            return 0;
        interop_sleep_ms(INTEROP_WAIT_STEP_MS);
    }
    return 0;
}

static int interop_wait_session(const char* log_path,
                                pid_t server,
                                pid_t client)
{
    unsigned int attempt = 0u;

    for (attempt = 0u; attempt < INTEROP_SESSION_STEPS; attempt++)
    {
        if (interop_file_contains(log_path,
                                  "event=server.host.peer.state") &&
            interop_file_contains(log_path, "status=ok value=11") &&
            interop_file_contains(log_path,
                                  "event=server.host.frame.presented") &&
            interop_file_contains(log_path, "event=server.rdpdr.ready"))
            return 1;
        if (!interop_process_alive(server) ||
            !interop_process_alive(client))
            return 0;
        interop_sleep_ms(INTEROP_WAIT_STEP_MS);
    }
    return 0;
}

static void interop_cleanup_files(const char* root,
                                  const char* drive_path,
                                  const char* mount_path,
                                  const char* marker_path,
                                  const char* server_log,
                                  const char* client_log,
                                  const char* first_display_log,
                                  const char* second_display_log)
{
    if (marker_path && marker_path[0] != '\0')
        (void)unlink(marker_path);
    if (server_log && server_log[0] != '\0')
        (void)unlink(server_log);
    if (client_log && client_log[0] != '\0')
        (void)unlink(client_log);
    if (first_display_log && first_display_log[0] != '\0')
        (void)unlink(first_display_log);
    if (second_display_log && second_display_log[0] != '\0')
        (void)unlink(second_display_log);
    if (drive_path && drive_path[0] != '\0')
        (void)rmdir(drive_path);
    if (mount_path && mount_path[0] != '\0')
        (void)rmdir(mount_path);
    if (root && root[0] != '\0')
        (void)rmdir(root);
}

int main(void)
{
    static const char marker[] = "synthetic drive marker\n";
    const char* external_client = getenv("LIBRDP_TEST_EXTERNAL_CLIENT");
    char root[] = "/tmp/librdp-x11-interop-XXXXXX";
    char drive_path[PATH_MAX] = {0};
    char mount_path[PATH_MAX] = {0};
    char marker_path[PATH_MAX] = {0};
    char server_log[PATH_MAX] = {0};
    char client_log[PATH_MAX] = {0};
    char first_display_log[PATH_MAX] = {0};
    char second_display_log[PATH_MAX] = {0};
    char server_display[32] = {0};
    char client_display[32] = {0};
    interop_processes processes;
    uint16_t port = 0u;
    int marker_file = -1;
    int result = 1;

    memset(&processes, 0, sizeof(processes));
    if (!external_client || external_client[0] == '\0')
    {
        fprintf(stderr,
                "skipped: LIBRDP_TEST_EXTERNAL_CLIENT is not configured\n");
        return INTEROP_SKIP_RETURN_CODE;
    }
    if (access(external_client, X_OK) != 0)
    {
        fprintf(stderr, "external client is not executable\n");
        return 1;
    }
    if (!mkdtemp(root) ||
        snprintf(drive_path, sizeof(drive_path), "%s/client-drive", root) <= 0 ||
        snprintf(mount_path, sizeof(mount_path), "%s/server-mount", root) <= 0 ||
        snprintf(marker_path,
                 sizeof(marker_path),
                 "%s/marker.txt",
                 drive_path) <= 0 ||
        snprintf(server_log, sizeof(server_log), "%s/server.log", root) <= 0 ||
        snprintf(client_log, sizeof(client_log), "%s/client.log", root) <= 0 ||
        snprintf(first_display_log,
                 sizeof(first_display_log),
                 "%s/xvfb-server.log",
                 root) <= 0 ||
        snprintf(second_display_log,
                 sizeof(second_display_log),
                 "%s/xvfb-client.log",
                 root) <= 0 ||
        mkdir(drive_path, 0700) != 0 ||
        mkdir(mount_path, 0700) != 0)
        goto cleanup;
    marker_file = open(marker_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (marker_file < 0 ||
        write(marker_file, marker, sizeof(marker) - 1u) !=
            (ssize_t)(sizeof(marker) - 1u))
        goto cleanup;
    close(marker_file);
    marker_file = -1;
    if (!interop_select_displays(server_display, client_display))
        goto cleanup;
    processes.server_display =
        interop_start_xvfb(server_display, first_display_log);
    if (processes.server_display <= 0 ||
        !interop_wait_for_display(server_display,
                                  processes.server_display))
        goto cleanup;
    processes.client_display =
        interop_start_xvfb(client_display, second_display_log);
    if (processes.client_display <= 0 ||
        !interop_wait_for_display(client_display,
                                  processes.client_display))
        goto cleanup;
    port = interop_select_port();
    if (port == 0u)
        goto cleanup;
    processes.server = interop_start_server(server_display,
                                            port,
                                            mount_path,
                                            server_log);
    if (processes.server <= 0 ||
        !interop_wait_server_ready(server_log, processes.server))
        goto cleanup;
    processes.client = interop_start_client(external_client,
                                            client_display,
                                            port,
                                            drive_path,
                                            client_log);
    if (processes.client <= 0 ||
        !interop_wait_session(server_log,
                              processes.server,
                              processes.client))
        goto cleanup;
    processes.drive_reader = interop_start_drive_reader(mount_path);
    if (processes.drive_reader <= 0 ||
        !interop_wait_child_success(&processes.drive_reader,
                                    processes.client,
                                    INTEROP_SESSION_STEPS))
        goto cleanup;
    if (!interop_file_contains(server_log, "event=server.host.drive.request") ||
        interop_file_contains(server_log, "status=protocol_error") ||
        interop_file_contains(server_log, "status=invalid_argument"))
        goto cleanup;
    result = 0;

cleanup:
    if (marker_file >= 0)
        close(marker_file);
    interop_stop_process(&processes.drive_reader);
    interop_stop_process(&processes.client);
    interop_stop_process(&processes.server);
    interop_stop_process(&processes.client_display);
    interop_stop_process(&processes.server_display);
    if (result != 0)
    {
        interop_dump_file("server", server_log);
        interop_dump_file("client", client_log);
    }
    if (getenv("LIBRDP_TEST_KEEP_TEMP"))
        fprintf(stderr, "temporary files retained at %s\n", root);
    else
    {
        interop_cleanup_files(root,
                              drive_path,
                              mount_path,
                              marker_path,
                              server_log,
                              client_log,
                              first_display_log,
                              second_display_log);
    }
    return result;
}
