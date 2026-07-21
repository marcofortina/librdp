/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
/*
 * Module: opt-in X11 server interoperability smoke.
 * Coverage: Standard, TLS and NLA activation, negotiated desktop geometry,
 * framebuffer delivery and client-drive traversal through an external client.
 * Bug classes: activation ordering, capture-size mismatches, channel startup
 * races, stalled child processes and incomplete drive request correlation.
 * Determinism: the test uses isolated Xvfb displays and synthetic credentials;
 * it is skipped unless an external client executable is supplied by environment.
 */

#include <X11/Xlib.h>
#include <X11/Xutil.h>
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

typedef enum interop_security
{
    INTEROP_SECURITY_STANDARD,
    INTEROP_SECURITY_TLS,
    INTEROP_SECURITY_NLA
} interop_security;

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

static int interop_paint_server_display(const char* display)
{
    Display* connection = NULL;
    GC graphics = NULL;
    Window root = 0;
    Pixmap pattern = 0;
    Colormap colormap = 0;
    XColor red;
    XColor green;
    XColor blue;
    XColor background;
    int screen = 0;
    int ok = 0;

    if (!display)
        return 0;
    connection = XOpenDisplay(display);
    if (!connection)
        return 0;
    screen = DefaultScreen(connection);
    root = RootWindow(connection, screen);
    colormap = DefaultColormap(connection, screen);
    pattern = XCreatePixmap(connection,
                            root,
                            1024u,
                            768u,
                            (unsigned int)DefaultDepth(connection, screen));
    if (pattern)
        graphics = XCreateGC(connection, pattern, 0u, NULL);
    memset(&red, 0, sizeof(red));
    memset(&green, 0, sizeof(green));
    memset(&blue, 0, sizeof(blue));
    memset(&background, 0, sizeof(background));
    red.red = 65535u;
    green.green = 65535u;
    blue.blue = 65535u;
    background.red = 8192u;
    background.green = 8192u;
    background.blue = 8192u;
    if (!pattern || !graphics || !XAllocColor(connection, colormap, &red) ||
        !XAllocColor(connection, colormap, &green) ||
        !XAllocColor(connection, colormap, &blue) ||
        !XAllocColor(connection, colormap, &background))
        goto cleanup;
    XSetForeground(connection, graphics, background.pixel);
    XFillRectangle(connection, pattern, graphics, 0, 0, 1024u, 768u);
    XSetForeground(connection, graphics, red.pixel);
    XFillRectangle(connection, pattern, graphics, 32, 32, 144u, 176u);
    XSetForeground(connection, graphics, green.pixel);
    XFillRectangle(connection, pattern, graphics, 224, 32, 144u, 176u);
    XSetForeground(connection, graphics, blue.pixel);
    XFillRectangle(connection, pattern, graphics, 416, 32, 144u, 176u);
    XSetWindowBackgroundPixmap(connection, root, pattern);
    XClearWindow(connection, root);
    XSetCloseDownMode(connection, RetainPermanent);
    XSync(connection, False);
    ok = 1;

cleanup:
    if (graphics)
        XFreeGC(connection, graphics);
    XCloseDisplay(connection);
    return ok;
}

static unsigned int interop_component(unsigned long pixel, unsigned long mask)
{
    unsigned int shift = 0u;
    unsigned long value = 0u;
    unsigned long maximum = 0u;

    if (mask == 0u)
        return 0u;
    while ((mask & 1u) == 0u)
    {
        mask >>= 1u;
        shift++;
    }
    value = (pixel >> shift) & mask;
    maximum = mask;
    return maximum == 0u ? 0u : (unsigned int)((value * 255u) / maximum);
}

static Window interop_client_window(Display* connection)
{
    Window root = 0;
    Window parent = 0;
    Window* children = NULL;
    Window selected = 0;
    unsigned int count = 0u;
    int screen = 0;

    if (!connection)
        return 0;
    screen = DefaultScreen(connection);
    root = RootWindow(connection, screen);
    if (!XQueryTree(connection, root, &root, &parent, &children, &count))
        return 0;
    for (unsigned int index = 0u; index < count; index++)
    {
        XWindowAttributes attributes;

        memset(&attributes, 0, sizeof(attributes));
        if (XGetWindowAttributes(connection, children[index], &attributes) &&
            attributes.map_state == IsViewable && attributes.width >= 600 &&
            attributes.height >= 400)
        {
            selected = children[index];
            break;
        }
    }
    if (children)
        XFree(children);
    return selected;
}

static int interop_request_client_close(const char* display)
{
    Display* connection = NULL;
    Window window = 0;
    Atom protocols = None;
    Atom delete_window = None;
    XEvent event;
    int sent = 0;

    if (!display)
        return 0;
    connection = XOpenDisplay(display);
    if (!connection)
        return 0;
    window = interop_client_window(connection);
    protocols = XInternAtom(connection, "WM_PROTOCOLS", False);
    delete_window = XInternAtom(connection, "WM_DELETE_WINDOW", False);
    if (window && protocols != None && delete_window != None)
    {
        memset(&event, 0, sizeof(event));
        event.xclient.type = ClientMessage;
        event.xclient.window = window;
        event.xclient.message_type = protocols;
        event.xclient.format = 32;
        event.xclient.data.l[0] = (long)delete_window;
        event.xclient.data.l[1] = CurrentTime;
        sent = XSendEvent(connection, window, False, NoEventMask, &event) != 0;
        XFlush(connection);
    }
    XCloseDisplay(connection);
    return sent;
}

static void
interop_write_framebuffer(const char* path, XImage* image, Visual* visual)
{
    FILE* file = NULL;
    int failed = 0;

    if (!path || !image || !visual)
        return;
    file = fopen(path, "wb");
    if (!file)
        return;
    if (fprintf(file, "P6\n%d %d\n255\n", image->width, image->height) > 0)
    {
        for (int y = 0; y < image->height && !failed; y++)
        {
            for (int x = 0; x < image->width; x++)
            {
                const unsigned long pixel = XGetPixel(image, x, y);
                const uint8_t color[3] = {
                    (uint8_t)interop_component(pixel, visual->red_mask),
                    (uint8_t)interop_component(pixel, visual->green_mask),
                    (uint8_t)interop_component(pixel, visual->blue_mask)};

                if (fwrite(color, 1u, sizeof(color), file) != sizeof(color))
                {
                    failed = 1;
                    break;
                }
            }
        }
    }
    else
        failed = 1;
    if (fclose(file) != 0)
        failed = 1;
    if (failed)
        (void)unlink(path);
}

static int interop_framebuffer_has_pattern(const char* display,
                                           const char* framebuffer_path)
{
    unsigned int attempt = 0u;
    unsigned int maximum_red = 0u;
    unsigned int maximum_green = 0u;
    unsigned int maximum_blue = 0u;
    int last_width = 0;
    int last_height = 0;

    for (attempt = 0u; attempt < INTEROP_STARTUP_STEPS; attempt++)
    {
        Display* connection = XOpenDisplay(display);
        Window window = 0;
        XWindowAttributes attributes;
        XImage* image = NULL;
        unsigned int red_count = 0u;
        unsigned int green_count = 0u;
        unsigned int blue_count = 0u;

        if (!connection)
            return 0;
        window = interop_client_window(connection);
        memset(&attributes, 0, sizeof(attributes));
        if (window && XGetWindowAttributes(connection, window, &attributes) &&
            attributes.visual && attributes.width >= 560 &&
            attributes.height >= 208)
        {
            last_width = attributes.width;
            last_height = attributes.height;
            image = XGetImage(
                connection, window, 0, 0, 560u, 208u, AllPlanes, ZPixmap);
        }
        if (image)
        {
            for (int y = 0; y < image->height; y += 2)
            {
                for (int x = 0; x < image->width; x += 2)
                {
                    const unsigned long pixel = XGetPixel(image, x, y);
                    const unsigned int red =
                        interop_component(pixel, attributes.visual->red_mask);
                    const unsigned int green =
                        interop_component(pixel, attributes.visual->green_mask);
                    const unsigned int blue =
                        interop_component(pixel, attributes.visual->blue_mask);

                    if (red > 180u && green < 80u && blue < 80u)
                        red_count++;
                    else if (green > 180u && red < 80u && blue < 80u)
                        green_count++;
                    else if (blue > 180u && red < 80u && green < 80u)
                        blue_count++;
                }
            }
            if (attempt + 1u == INTEROP_STARTUP_STEPS)
                interop_write_framebuffer(
                    framebuffer_path, image, attributes.visual);
            XDestroyImage(image);
        }
        XCloseDisplay(connection);
        if (red_count > maximum_red)
            maximum_red = red_count;
        if (green_count > maximum_green)
            maximum_green = green_count;
        if (blue_count > maximum_blue)
            maximum_blue = blue_count;
        if (red_count > 1000u && green_count > 1000u && blue_count > 1000u)
            return 1;
        interop_sleep_ms(INTEROP_WAIT_STEP_MS);
    }
    fprintf(stderr,
            "framebuffer pattern not observed display=%s window=%dx%d red=%u "
            "green=%u blue=%u\n",
            display,
            last_width,
            last_height,
            maximum_red,
            maximum_green,
            maximum_blue);
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

static const char* interop_security_name(interop_security security)
{
    switch (security)
    {
    case INTEROP_SECURITY_STANDARD:
        return "standard";
    case INTEROP_SECURITY_TLS:
        return "tls";
    case INTEROP_SECURITY_NLA:
        return "nla";
    default:
        return NULL;
    }
}

static int interop_generate_tls_material(const char* certificate_path,
                                         const char* private_key_path,
                                         const char* log_path)
{
    pid_t child = 0;
    int status = 0;

    if (!certificate_path || !private_key_path || !log_path)
        return 0;
    child = fork();
    if (child < 0)
        return 0;
    if (child == 0)
    {
        int log = interop_open_log(log_path);

        if (log < 0 || dup2(log, STDOUT_FILENO) < 0 ||
            dup2(log, STDERR_FILENO) < 0)
            _exit(126);
        if (log > STDERR_FILENO)
            close(log);
        execl(LIBRDP_TEST_OPENSSL_PATH,
              LIBRDP_TEST_OPENSSL_PATH,
              "req",
              "-x509",
              "-newkey",
              "rsa:2048",
              "-sha256",
              "-nodes",
              "-days",
              "1",
              "-subj",
              "/CN=localhost",
              "-addext",
              "basicConstraints=critical,CA:TRUE",
              "-addext",
              "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
              "-addext",
              "extendedKeyUsage=serverAuth",
              "-addext",
              "subjectAltName=DNS:localhost",
              "-keyout",
              private_key_path,
              "-out",
              certificate_path,
              (char*)NULL);
        _exit(127);
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return 0;
    return chmod(private_key_path, 0600) == 0 &&
           chmod(certificate_path, 0600) == 0;
}

static pid_t interop_start_server(const char* display,
                                  uint16_t port,
                                  const char* mount_path,
                                  interop_security security,
                                  const char* certificate_path,
                                  const char* private_key_path,
                                  const char* log_path)
{
    char port_text[16];
    char* arguments[40];
    size_t argument_count = 0u;
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
        setenv("LIBRDP_TRACE_HEX_BYTES", "96", 1) != 0 ||
        (security == INTEROP_SECURITY_NLA &&
         setenv("LIBRDP_TEST_SERVER_PASSWORD", "interop-secret", 1) != 0))
        _exit(126);
    arguments[argument_count++] = (char*)LIBRDP_TEST_X11_SERVER_PATH;
    arguments[argument_count++] = (char*)"--display";
    arguments[argument_count++] = (char*)display;
    arguments[argument_count++] = (char*)"--bind";
    arguments[argument_count++] = (char*)"127.0.0.1";
    arguments[argument_count++] = (char*)"--port";
    arguments[argument_count++] = port_text;
    arguments[argument_count++] = (char*)"--security";
    arguments[argument_count++] = (char*)interop_security_name(security);
    if (security == INTEROP_SECURITY_STANDARD)
        arguments[argument_count++] = (char*)"--allow-standard-security";
    else
    {
        arguments[argument_count++] = (char*)"--tls-cert";
        arguments[argument_count++] = (char*)certificate_path;
        arguments[argument_count++] = (char*)"--tls-key";
        arguments[argument_count++] = (char*)private_key_path;
    }
    if (security == INTEROP_SECURITY_NLA)
    {
        arguments[argument_count++] = (char*)"--user";
        arguments[argument_count++] = (char*)"interop-user";
        arguments[argument_count++] = (char*)"--domain";
        arguments[argument_count++] = (char*)"interop-domain";
        arguments[argument_count++] = (char*)"--password-env";
        arguments[argument_count++] = (char*)"LIBRDP_TEST_SERVER_PASSWORD";
    }
    arguments[argument_count++] = (char*)"--allow-capture";
    arguments[argument_count++] = (char*)"--allow-input";
    arguments[argument_count++] = (char*)"--allow-clipboard";
    arguments[argument_count++] = (char*)"--allow-drive";
    arguments[argument_count++] = (char*)"--drive-mount";
    arguments[argument_count++] = (char*)mount_path;
    arguments[argument_count++] = (char*)"--max-peers";
    arguments[argument_count++] = (char*)"1";
    arguments[argument_count++] = (char*)"--max-fps";
    arguments[argument_count++] = (char*)"30";
    arguments[argument_count] = NULL;
    execv(LIBRDP_TEST_X11_SERVER_PATH, arguments);
    _exit(127);
}

static pid_t interop_start_client(const char* executable,
                                  const char* display,
                                  uint16_t port,
                                  const char* drive_path,
                                  interop_security security,
                                  const char* certificate_path,
                                  const char* log_path)
{
    char endpoint[64];
    char drive[PATH_MAX + 32u];
    char security_option[32];
    char* arguments[20];
    size_t argument_count = 0u;
    int endpoint_length = 0;
    int drive_length = 0;
    int security_length = 0;
    pid_t child = 0;

    endpoint_length = snprintf(
        endpoint,
        sizeof(endpoint),
        "/v:%s:%u",
        security == INTEROP_SECURITY_STANDARD ? "127.0.0.1" : "localhost",
        (unsigned int)port);
    drive_length =
        snprintf(drive, sizeof(drive), "/drive:SMOKE,%s", drive_path);
    security_length = snprintf(security_option,
                               sizeof(security_option),
                               "/sec:%s",
                               security == INTEROP_SECURITY_STANDARD
                                   ? "rdp"
                                   : interop_security_name(security));
    if (endpoint_length <= 0 || (size_t)endpoint_length >= sizeof(endpoint) ||
        drive_length <= 0 || (size_t)drive_length >= sizeof(drive) ||
        security_length <= 0 ||
        (size_t)security_length >= sizeof(security_option))
        return -1;
    arguments[argument_count++] = (char*)executable;
    arguments[argument_count++] = endpoint;
    arguments[argument_count++] = (char*)"/u:interop-user";
    if (security == INTEROP_SECURITY_NLA)
    {
        arguments[argument_count++] = (char*)"/d:interop-domain";
        arguments[argument_count++] = (char*)"/auth-pkg-list:!kerberos";
    }
    arguments[argument_count++] = (char*)"/p:interop-secret";
    arguments[argument_count++] = security_option;
    if (security != INTEROP_SECURITY_STANDARD)
        arguments[argument_count++] = (char*)"/cert:deny";
    arguments[argument_count++] = (char*)"/size:640x480";
    arguments[argument_count++] = drive;
    arguments[argument_count++] = (char*)"/gfx:off";
    arguments[argument_count++] = (char*)"-multitransport";
    arguments[argument_count++] = (char*)"-heartbeat";
    arguments[argument_count++] = (char*)"/network:lan";
    arguments[argument_count++] = (char*)"/audio-mode:2";
    arguments[argument_count++] = (char*)"/log-level:INFO";
    arguments[argument_count] = NULL;
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
        (security != INTEROP_SECURITY_STANDARD &&
         setenv("SSL_CERT_FILE", certificate_path, 1) != 0))
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

static int interop_wait_clean_exit(pid_t* process, unsigned int attempts)
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
                                  const char* certificate_path,
                                  const char* private_key_path,
                                  const char* openssl_log,
                                  const char* framebuffer_path,
                                  const char* server_log,
                                  const char* client_log,
                                  const char* first_display_log,
                                  const char* second_display_log)
{
    if (marker_path && marker_path[0] != '\0')
        (void)unlink(marker_path);
    if (certificate_path && certificate_path[0] != '\0')
        (void)unlink(certificate_path);
    if (private_key_path && private_key_path[0] != '\0')
        (void)unlink(private_key_path);
    if (openssl_log && openssl_log[0] != '\0')
        (void)unlink(openssl_log);
    if (framebuffer_path && framebuffer_path[0] != '\0')
        (void)unlink(framebuffer_path);
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

int main(int argc, char** argv)
{
    static const char marker[] = "synthetic drive marker\n";
    const char* external_client = getenv("LIBRDP_TEST_EXTERNAL_CLIENT");
    char root[] = "/tmp/librdp-x11-interop-XXXXXX";
    char drive_path[PATH_MAX] = {0};
    char mount_path[PATH_MAX] = {0};
    char marker_path[PATH_MAX] = {0};
    char certificate_path[PATH_MAX] = {0};
    char private_key_path[PATH_MAX] = {0};
    char openssl_log[PATH_MAX] = {0};
    char framebuffer_path[PATH_MAX] = {0};
    char server_log[PATH_MAX] = {0};
    char client_log[PATH_MAX] = {0};
    char first_display_log[PATH_MAX] = {0};
    char second_display_log[PATH_MAX] = {0};
    char server_display[32] = {0};
    char client_display[32] = {0};
    interop_processes processes;
    interop_security security = INTEROP_SECURITY_STANDARD;
    uint16_t port = 0u;
    int marker_file = -1;
    int result = 1;

    memset(&processes, 0, sizeof(processes));
    if (argc == 2 && strcmp(argv[1], "tls") == 0)
        security = INTEROP_SECURITY_TLS;
    else if (argc == 2 && strcmp(argv[1], "nla") == 0)
        security = INTEROP_SECURITY_NLA;
    else if (argc != 1 && !(argc == 2 && strcmp(argv[1], "standard") == 0))
    {
        fprintf(stderr, "usage: %s [standard|tls|nla]\n", argv[0]);
        return 2;
    }
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
        snprintf(drive_path, sizeof(drive_path), "%s/client-drive", root) <=
            0 ||
        snprintf(mount_path, sizeof(mount_path), "%s/server-mount", root) <=
            0 ||
        snprintf(
            marker_path, sizeof(marker_path), "%s/marker.txt", drive_path) <=
            0 ||
        snprintf(certificate_path,
                 sizeof(certificate_path),
                 "%s/server.pem",
                 root) <= 0 ||
        snprintf(private_key_path,
                 sizeof(private_key_path),
                 "%s/server.key",
                 root) <= 0 ||
        snprintf(openssl_log, sizeof(openssl_log), "%s/openssl.log", root) <=
            0 ||
        snprintf(framebuffer_path,
                 sizeof(framebuffer_path),
                 "%s/client-frame.ppm",
                 root) <= 0 ||
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
    if (security != INTEROP_SECURITY_STANDARD &&
        !interop_generate_tls_material(
            certificate_path, private_key_path, openssl_log))
        goto cleanup;
    if (!interop_select_displays(server_display, client_display))
        goto cleanup;
    processes.server_display =
        interop_start_xvfb(server_display, first_display_log);
    if (processes.server_display <= 0 ||
        !interop_wait_for_display(server_display, processes.server_display) ||
        !interop_paint_server_display(server_display))
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
                                            security,
                                            certificate_path,
                                            private_key_path,
                                            server_log);
    if (processes.server <= 0 ||
        !interop_wait_server_ready(server_log, processes.server))
        goto cleanup;
    processes.client = interop_start_client(external_client,
                                            client_display,
                                            port,
                                            drive_path,
                                            security,
                                            certificate_path,
                                            client_log);
    if (processes.client <= 0 ||
        !interop_wait_session(server_log, processes.server, processes.client) ||
        !interop_framebuffer_has_pattern(client_display, framebuffer_path))
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
    if (!interop_request_client_close(client_display) ||
        !interop_wait_clean_exit(&processes.client, INTEROP_STARTUP_STEPS))
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
                              certificate_path,
                              private_key_path,
                              openssl_log,
                              framebuffer_path,
                              server_log,
                              client_log,
                              first_display_log,
                              second_display_log);
    }
    return result;
}
