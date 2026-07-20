/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: isolated X11 viewer graphics integration smoke.
 * Coverage: actual viewer process, X11 window presentation, Standard Security,
 * bitmap codecs, RemoteFX, and negotiated Graphics Pipeline codecs.
 * Bug classes: decoder output never presented, black windows, unstable frames,
 * row or channel corruption, process teardown failures, and trace errors.
 * Determinism: every family is rendered twice on a private Xvfb server and the
 * normalized RGB hashes of the viewer window must match.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <X11/Xlib.h>
#include <X11/Xutil.h>

#include <openssl/evp.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define VIEWER_SMOKE_SHA256_BYTES 32u
#define VIEWER_SMOKE_WAIT_STEPS 600u
#define VIEWER_SMOKE_STABLE_CAPTURES 4u
#define VIEWER_SMOKE_STEP_MS 25u

typedef struct viewer_smoke_family
{
    const char* name;
    uint32_t width;
    uint32_t height;
} viewer_smoke_family;

typedef struct viewer_smoke_processes
{
    pid_t xvfb;
    pid_t server;
    pid_t viewer;
} viewer_smoke_processes;

static void viewer_smoke_sleep_ms(unsigned int milliseconds)
{
    struct timespec delay;

    delay.tv_sec = (time_t)(milliseconds / 1000u);
    delay.tv_nsec =
        (long)(milliseconds % 1000u) * 1000000L;
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR)
    {
    }
}

static int viewer_smoke_process_alive(pid_t process)
{
    if (process <= 0)
        return 0;
    return kill(process, 0) == 0 || errno == EPERM;
}

static void viewer_smoke_stop_process(pid_t* process)
{
    unsigned int attempt = 0u;

    if (!process || *process <= 0)
        return;
    (void)kill(*process, SIGTERM);
    for (attempt = 0u; attempt < 40u; attempt++)
    {
        int status = 0;
        pid_t waited = waitpid(*process, &status, WNOHANG);

        if (waited == *process ||
            (waited < 0 && errno == ECHILD))
        {
            *process = -1;
            return;
        }
        viewer_smoke_sleep_ms(VIEWER_SMOKE_STEP_MS);
    }
    (void)kill(*process, SIGKILL);
    (void)waitpid(*process, NULL, 0);
    *process = -1;
}

static int viewer_smoke_wait_success(pid_t* process,
                                     unsigned int steps)
{
    unsigned int step = 0u;

    if (!process || *process <= 0)
        return 0;
    for (step = 0u; step < steps; step++)
    {
        int status = 0;
        pid_t waited = waitpid(*process, &status, WNOHANG);

        if (waited == *process)
        {
            *process = -1;
            return WIFEXITED(status) &&
                   WEXITSTATUS(status) == 0;
        }
        if (waited < 0)
            return 0;
        viewer_smoke_sleep_ms(VIEWER_SMOKE_STEP_MS);
    }
    return 0;
}

static int viewer_smoke_open_log(const char* path)
{
    if (!path)
        return -1;
    return open(path,
                O_WRONLY | O_CREAT | O_TRUNC,
                S_IRUSR | S_IWUSR);
}

static int viewer_smoke_file_contains(const char* path,
                                      const char* needle)
{
    FILE* file = NULL;
    char line[2048];

    if (!path || !needle)
        return 0;
    file = fopen(path, "rb");
    if (!file)
        return 0;
    while (fgets(line, sizeof(line), file))
    {
        if (strstr(line, needle))
        {
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}

static void viewer_smoke_dump_file(const char* label,
                                   const char* path)
{
    FILE* file = NULL;
    char buffer[4096];
    size_t count = 0u;

    fprintf(stderr, "--- %s ---\n", label ? label : "log");
    file = path ? fopen(path, "rb") : NULL;
    if (!file)
    {
        fprintf(stderr, "unavailable\n");
        return;
    }
    while ((count = fread(buffer, 1u, sizeof(buffer), file)) > 0u)
        (void)fwrite(buffer, 1u, count, stderr);
    fclose(file);
}

static int viewer_smoke_choose_display(char display_name[32])
{
    unsigned int attempt = 0u;

    if (!display_name)
        return 0;
    for (attempt = 0u; attempt < 100u; attempt++)
    {
        unsigned int number =
            420u + ((unsigned int)getpid() + attempt) % 400u;
        char socket_path[PATH_MAX];
        int path_length = snprintf(socket_path,
                                   sizeof(socket_path),
                                   "/tmp/.X11-unix/X%u",
                                   number);

        if (path_length <= 0 ||
            (size_t)path_length >= sizeof(socket_path))
            return 0;
        if (access(socket_path, F_OK) == 0)
            continue;
        return snprintf(display_name,
                        32u,
                        ":%u",
                        number) > 0;
    }
    return 0;
}

static pid_t viewer_smoke_start_xvfb(const char* display_name,
                                     const char* log_path)
{
    pid_t child = fork();

    if (child != 0)
        return child;
    {
        int log = viewer_smoke_open_log(log_path);

        if (log < 0 ||
            dup2(log, STDOUT_FILENO) < 0 ||
            dup2(log, STDERR_FILENO) < 0)
            _exit(126);
        if (log > STDERR_FILENO)
            close(log);
    }
    execl(LIBRDP_TEST_XVFB_PATH,
          LIBRDP_TEST_XVFB_PATH,
          display_name,
          "-screen",
          "0",
          "640x480x24",
          "-nolisten",
          "tcp",
          "-ac",
          (char*)NULL);
    _exit(127);
}

static Display* viewer_smoke_wait_display(const char* display_name,
                                          pid_t xvfb)
{
    unsigned int step = 0u;

    for (step = 0u; step < VIEWER_SMOKE_WAIT_STEPS; step++)
    {
        Display* display = XOpenDisplay(display_name);

        if (display)
            return display;
        if (!viewer_smoke_process_alive(xvfb))
            return NULL;
        viewer_smoke_sleep_ms(VIEWER_SMOKE_STEP_MS);
    }
    return NULL;
}

static pid_t viewer_smoke_start_server(const char* family,
                                       const char* state_path,
                                       const char* log_path)
{
    pid_t child = fork();

    if (child != 0)
        return child;
    {
        int log = viewer_smoke_open_log(log_path);

        if (log < 0 ||
            dup2(log, STDOUT_FILENO) < 0 ||
            dup2(log, STDERR_FILENO) < 0)
            _exit(126);
        if (log > STDERR_FILENO)
            close(log);
    }
    execl(LIBRDP_TEST_GRAPHICS_SERVER_PATH,
          LIBRDP_TEST_GRAPHICS_SERVER_PATH,
          "viewer-graphics-server",
          family,
          state_path,
          (char*)NULL);
    _exit(127);
}

static int viewer_smoke_read_state(const char* path,
                                   uint16_t* port,
                                   int* frame_ready)
{
    FILE* file = NULL;
    unsigned int parsed_port = 0u;
    unsigned int parsed_ready = 0u;
    int fields = 0;

    if (!path || !port || !frame_ready)
        return 0;
    file = fopen(path, "rb");
    if (!file)
        return 0;
    fields = fscanf(file,
                    "port=%u\nframe_ready=%u\n",
                    &parsed_port,
                    &parsed_ready);
    fclose(file);
    if (fields != 2 || parsed_port == 0u ||
        parsed_port > UINT16_MAX || parsed_ready > 1u)
        return 0;
    *port = (uint16_t)parsed_port;
    *frame_ready = parsed_ready ? 1 : 0;
    return 1;
}

static int viewer_smoke_wait_state(const char* state_path,
                                   pid_t server,
                                   int require_frame,
                                   uint16_t* port)
{
    unsigned int step = 0u;

    for (step = 0u; step < VIEWER_SMOKE_WAIT_STEPS; step++)
    {
        uint16_t parsed_port = 0u;
        int frame_ready = 0;

        if (viewer_smoke_read_state(state_path,
                                    &parsed_port,
                                    &frame_ready) &&
            (!require_frame || frame_ready))
        {
            *port = parsed_port;
            return 1;
        }
        if (!viewer_smoke_process_alive(server))
            return 0;
        viewer_smoke_sleep_ms(VIEWER_SMOKE_STEP_MS);
    }
    return 0;
}

static pid_t viewer_smoke_start_viewer(const char* display_name,
                                       uint16_t port,
                                       uint32_t width,
                                       uint32_t height,
                                       const char* log_path)
{
    char port_text[16];
    char width_text[16];
    char height_text[16];
    pid_t child = 0;

    if (snprintf(port_text,
                 sizeof(port_text),
                 "%u",
                 (unsigned int)port) <= 0 ||
        snprintf(width_text,
                 sizeof(width_text),
                 "%u",
                 width) <= 0 ||
        snprintf(height_text,
                 sizeof(height_text),
                 "%u",
                 height) <= 0)
        return -1;
    child = fork();
    if (child != 0)
        return child;
    {
        int log = viewer_smoke_open_log(log_path);

        if (log < 0 ||
            dup2(log, STDOUT_FILENO) < 0 ||
            dup2(log, STDERR_FILENO) < 0)
            _exit(126);
        if (log > STDERR_FILENO)
            close(log);
    }
    if (setenv("DISPLAY", display_name, 1) != 0 ||
        setenv("LIBRDP_TRACE_CLIENT", "1", 1) != 0 ||
        setenv("LIBRDP_TRACE_PROTOCOL", "1", 1) != 0 ||
        setenv("LIBRDP_TRACE_LEVEL", "trace", 1) != 0 ||
        setenv("LIBRDP_TRACE_HEX_BYTES", "0", 1) != 0)
        _exit(126);
    execl(LIBRDP_TEST_VIEWER_PATH,
          LIBRDP_TEST_VIEWER_PATH,
          "--target",
          "127.0.0.1",
          "--port",
          port_text,
          "--user",
          "graphics-smoke-user",
          "--security",
          "rdp",
          "--width",
          width_text,
          "--height",
          height_text,
          (char*)NULL);
    _exit(127);
}

static Window viewer_smoke_find_window(Display* display,
                                       pid_t viewer)
{
    unsigned int step = 0u;

    if (!display)
        return None;
    for (step = 0u; step < VIEWER_SMOKE_WAIT_STEPS; step++)
    {
        Window root = DefaultRootWindow(display);
        Window root_return = None;
        Window parent_return = None;
        Window* children = NULL;
        unsigned int child_count = 0u;
        unsigned int child_index = 0u;
        Window found = None;

        XSync(display, False);
        if (XQueryTree(display,
                       root,
                       &root_return,
                       &parent_return,
                       &children,
                       &child_count))
        {
            for (child_index = 0u;
                 child_index < child_count;
                 child_index++)
            {
                char* name = NULL;

                if (XFetchName(display,
                               children[child_index],
                               &name) &&
                    name &&
                    strcmp(name, "librdp-viewer") == 0)
                    found = children[child_index];
                if (name)
                    XFree(name);
                if (found != None)
                    break;
            }
        }
        if (children)
            XFree(children);
        if (found != None)
            return found;
        if (!viewer_smoke_process_alive(viewer))
            return None;
        viewer_smoke_sleep_ms(VIEWER_SMOKE_STEP_MS);
    }
    return None;
}

static uint8_t viewer_smoke_channel(unsigned long pixel,
                                    unsigned long mask)
{
    unsigned int shift = 0u;
    unsigned long maximum = 0u;
    unsigned long value = 0u;

    if (mask == 0u)
        return 0u;
    while ((mask & 1u) == 0u)
    {
        mask >>= 1u;
        shift++;
    }
    maximum = mask;
    value = (pixel >> shift) & maximum;
    return (uint8_t)((value * 255u + maximum / 2u) /
                     maximum);
}

static int viewer_smoke_capture(Display* display,
                                Window window,
                                uint32_t width,
                                uint32_t height,
                                uint8_t digest[VIEWER_SMOKE_SHA256_BYTES],
                                size_t* nonblack)
{
    XWindowAttributes attributes;
    XImage* image = NULL;
    uint8_t* rgb = NULL;
    size_t rgb_length = 0u;
    size_t colored = 0u;
    unsigned int digest_length = 0u;
    uint32_t y = 0u;
    uint32_t x = 0u;
    int result = 0;

    if (!display || window == None || !digest || !nonblack ||
        width == 0u || height == 0u ||
        (size_t)width > SIZE_MAX / (size_t)height ||
        (size_t)width * (size_t)height > SIZE_MAX / 3u)
        return 0;
    XSync(display, False);
    if (!XGetWindowAttributes(display, window, &attributes) ||
        attributes.map_state != IsViewable ||
        attributes.width != (int)width ||
        attributes.height != (int)height)
        return 0;
    image = XGetImage(display,
                      window,
                      0,
                      0,
                      width,
                      height,
                      AllPlanes,
                      ZPixmap);
    if (!image)
        return 0;
    rgb_length = (size_t)width * (size_t)height * 3u;
    rgb = (uint8_t*)malloc(rgb_length);
    if (!rgb)
        goto cleanup;
    for (y = 0u; y < height; y++)
    {
        for (x = 0u; x < width; x++)
        {
            unsigned long pixel =
                XGetPixel(image, (int)x, (int)y);
            size_t offset =
                ((size_t)y * width + x) * 3u;
            uint8_t red =
                viewer_smoke_channel(pixel, image->red_mask);
            uint8_t green =
                viewer_smoke_channel(pixel, image->green_mask);
            uint8_t blue =
                viewer_smoke_channel(pixel, image->blue_mask);

            rgb[offset] = red;
            rgb[offset + 1u] = green;
            rgb[offset + 2u] = blue;
            if (red != 0u || green != 0u || blue != 0u)
                colored++;
        }
    }
    if (EVP_Digest(rgb,
                   rgb_length,
                   digest,
                   &digest_length,
                   EVP_sha256(),
                   NULL) != 1 ||
        digest_length != VIEWER_SMOKE_SHA256_BYTES)
        goto cleanup;
    *nonblack = colored;
    result = 1;

cleanup:
    free(rgb);
    XDestroyImage(image);
    return result;
}

static int viewer_smoke_wait_stable_capture(
    Display* display,
    Window window,
    uint32_t width,
    uint32_t height,
    pid_t viewer,
    uint8_t digest[VIEWER_SMOKE_SHA256_BYTES],
    size_t* nonblack)
{
    uint8_t previous[VIEWER_SMOKE_SHA256_BYTES];
    unsigned int stable = 0u;
    unsigned int step = 0u;

    memset(previous, 0, sizeof(previous));
    for (step = 0u; step < VIEWER_SMOKE_WAIT_STEPS; step++)
    {
        uint8_t current[VIEWER_SMOKE_SHA256_BYTES];
        size_t current_nonblack = 0u;

        if (viewer_smoke_capture(display,
                                 window,
                                 width,
                                 height,
                                 current,
                                 &current_nonblack) &&
            current_nonblack > 0u)
        {
            if (stable > 0u &&
                memcmp(previous,
                       current,
                       sizeof(previous)) == 0)
                stable++;
            else
                stable = 1u;
            memcpy(previous, current, sizeof(previous));
            if (stable >= VIEWER_SMOKE_STABLE_CAPTURES)
            {
                memcpy(digest, current, sizeof(current));
                *nonblack = current_nonblack;
                return 1;
            }
        }
        else
            stable = 0u;
        if (!viewer_smoke_process_alive(viewer))
            return 0;
        viewer_smoke_sleep_ms(VIEWER_SMOKE_STEP_MS);
    }
    return 0;
}

static int viewer_smoke_close_window(Display* display,
                                     Window window)
{
    XEvent event;
    Atom protocols = None;
    Atom delete_window = None;

    if (!display || window == None)
        return 0;
    protocols = XInternAtom(display, "WM_PROTOCOLS", False);
    delete_window =
        XInternAtom(display, "WM_DELETE_WINDOW", False);
    if (protocols == None || delete_window == None)
        return 0;
    memset(&event, 0, sizeof(event));
    event.xclient.type = ClientMessage;
    event.xclient.window = window;
    event.xclient.message_type = protocols;
    event.xclient.format = 32;
    event.xclient.data.l[0] = (long)delete_window;
    event.xclient.data.l[1] = CurrentTime;
    if (!XSendEvent(display,
                    window,
                    False,
                    NoEventMask,
                    &event))
        return 0;
    XFlush(display);
    return 1;
}

static void viewer_smoke_print_digest(
    const char* family,
    unsigned int run,
    const uint8_t digest[VIEWER_SMOKE_SHA256_BYTES],
    size_t nonblack)
{
    size_t index = 0u;

    fprintf(stdout,
            "family=%s run=%u nonblack=%llu sha256=",
            family,
            run,
            (unsigned long long)nonblack);
    for (index = 0u;
         index < VIEWER_SMOKE_SHA256_BYTES;
         index++)
        fprintf(stdout, "%02x", digest[index]);
    fputc('\n', stdout);
}

static int viewer_smoke_run_once(
    Display* display,
    const char* root,
    const viewer_smoke_family* family,
    unsigned int run,
    uint8_t digest[VIEWER_SMOKE_SHA256_BYTES],
    size_t* nonblack)
{
    char state_path[PATH_MAX];
    char server_log[PATH_MAX];
    char viewer_log[PATH_MAX];
    viewer_smoke_processes processes;
    Window window = None;
    uint16_t port = 0u;
    int frame_ready = 0;
    int result = 0;

    memset(&processes, 0, sizeof(processes));
    if (snprintf(state_path,
                 sizeof(state_path),
                 "%s/%s-%u.state",
                 root,
                 family->name,
                 run) <= 0 ||
        snprintf(server_log,
                 sizeof(server_log),
                 "%s/%s-%u-server.log",
                 root,
                 family->name,
                 run) <= 0 ||
        snprintf(viewer_log,
                 sizeof(viewer_log),
                 "%s/%s-%u-viewer.log",
                 root,
                 family->name,
                 run) <= 0)
        return 0;
    processes.server =
        viewer_smoke_start_server(family->name,
                                  state_path,
                                  server_log);
    if (processes.server <= 0 ||
        !viewer_smoke_wait_state(state_path,
                                 processes.server,
                                 0,
                                 &port))
        goto cleanup;
    processes.viewer =
        viewer_smoke_start_viewer(DisplayString(display),
                                  port,
                                  family->width,
                                  family->height,
                                  viewer_log);
    if (processes.viewer <= 0)
        goto cleanup;
    window = viewer_smoke_find_window(display,
                                      processes.viewer);
    if (window == None ||
        !viewer_smoke_wait_state(state_path,
                                 processes.server,
                                 1,
                                 &port))
        goto cleanup;
    frame_ready = 1;
    if (!viewer_smoke_wait_stable_capture(
            display,
            window,
            family->width,
            family->height,
            processes.viewer,
            digest,
            nonblack))
        goto cleanup;
    viewer_smoke_print_digest(family->name,
                              run,
                              digest,
                              *nonblack);
    if (!viewer_smoke_close_window(display, window) ||
        !viewer_smoke_wait_success(&processes.viewer,
                                   VIEWER_SMOKE_WAIT_STEPS) ||
        !viewer_smoke_wait_success(&processes.server,
                                   VIEWER_SMOKE_WAIT_STEPS))
        goto cleanup;
    if (!viewer_smoke_file_contains(
            viewer_log,
            "event=client.connect.done") ||
        !viewer_smoke_file_contains(
            viewer_log,
            "event=x11.surface.draw.done") ||
        viewer_smoke_file_contains(
            viewer_log,
            "status=protocol_error") ||
        viewer_smoke_file_contains(
            viewer_log,
            "event=client.connect.failed"))
        goto cleanup;
    result = 1;

cleanup:
    if (!result)
    {
        fprintf(stderr,
                "viewer graphics smoke failed family=%s run=%u frame_ready=%u\n",
                family->name,
                run,
                frame_ready ? 1u : 0u);
        viewer_smoke_dump_file("server", server_log);
        viewer_smoke_dump_file("viewer", viewer_log);
    }
    viewer_smoke_stop_process(&processes.viewer);
    viewer_smoke_stop_process(&processes.server);
    if (!getenv("LIBRDP_TEST_KEEP_TEMP"))
    {
        (void)unlink(state_path);
        (void)unlink(server_log);
        (void)unlink(viewer_log);
    }
    return result;
}

int main(void)
{
    static const viewer_smoke_family families[] = {
        {"bitmap", 200u, 200u},
        {"nscodec", 200u, 200u},
        {"remotefx", 200u, 200u},
        {"planar", 201u, 201u},
        {"progressive", 200u, 200u},
        {"multi-surface", 200u, 200u},
        {"clearcodec", 200u, 200u},
#ifdef LIBRDP_TEST_HAVE_AVC
        {"avc", 200u, 200u},
#endif
    };
    char root[] = "/tmp/librdp-viewer-graphics-XXXXXX";
    char display_name[32];
    char xvfb_log[PATH_MAX];
    viewer_smoke_processes processes;
    Display* display = NULL;
    size_t family_index = 0u;
    int result = 1;

    memset(&processes, 0, sizeof(processes));
    memset(display_name, 0, sizeof(display_name));
    if (!mkdtemp(root) ||
        snprintf(xvfb_log,
                 sizeof(xvfb_log),
                 "%s/xvfb.log",
                 root) <= 0 ||
        !viewer_smoke_choose_display(display_name))
        goto cleanup;
    processes.xvfb =
        viewer_smoke_start_xvfb(display_name, xvfb_log);
    if (processes.xvfb <= 0)
        goto cleanup;
    display = viewer_smoke_wait_display(display_name,
                                        processes.xvfb);
    if (!display)
        goto cleanup;
    for (family_index = 0u;
         family_index <
             sizeof(families) / sizeof(families[0]);
         family_index++)
    {
        uint8_t first[VIEWER_SMOKE_SHA256_BYTES];
        uint8_t second[VIEWER_SMOKE_SHA256_BYTES];
        size_t first_nonblack = 0u;
        size_t second_nonblack = 0u;

        if (!viewer_smoke_run_once(display,
                                   root,
                                   &families[family_index],
                                   1u,
                                   first,
                                   &first_nonblack) ||
            !viewer_smoke_run_once(display,
                                   root,
                                   &families[family_index],
                                   2u,
                                   second,
                                   &second_nonblack) ||
            first_nonblack != second_nonblack ||
            memcmp(first, second, sizeof(first)) != 0)
        {
            fprintf(stderr,
                    "viewer graphics output is not stable family=%s\n",
                    families[family_index].name);
            goto cleanup;
        }
    }
    result = 0;

cleanup:
    if (display)
        XCloseDisplay(display);
    viewer_smoke_stop_process(&processes.xvfb);
    if (result != 0)
        viewer_smoke_dump_file("xvfb", xvfb_log);
    if (!getenv("LIBRDP_TEST_KEEP_TEMP") &&
        root[0] != '\0')
    {
        (void)unlink(xvfb_log);
        (void)rmdir(root);
    }
    else if (root[0] != '\0')
        fprintf(stderr, "temporary files retained at %s\n", root);
    return result;
}
