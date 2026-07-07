#include <librdp/librdp.h>

#include "common/trace.h"

#include <X11/Xlib.h>
#include <X11/Xutil.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct x11_app
{
    Display* display;
    int screen;
    Window window;
    GC gc;
    Atom wm_delete;
    librdp_session* session;
    int running;
    int dirty;
} x11_app;

static int parse_u16(const char* text, uint16_t* value)
{
    char* end = NULL;
    unsigned long parsed = 0;
    if (!text || !value)
        return 0;
    parsed = strtoul(text, &end, 10);
    if (!end || *end != '\0' || parsed == 0 || parsed > 65535ul)
        return 0;
    *value = (uint16_t)parsed;
    return 1;
}

static int parse_u32(const char* text, uint32_t* value)
{
    char* end = NULL;
    unsigned long parsed = 0;
    if (!text || !value)
        return 0;
    parsed = strtoul(text, &end, 10);
    if (!end || *end != '\0' || parsed == 0 || parsed > 8192ul)
        return 0;
    *value = (uint32_t)parsed;
    return 1;
}

static int parse_security(const char* text, librdp_security_mode* mode)
{
    if (!text || !mode)
        return 0;
    if (strcmp(text, "auto") == 0)
        *mode = LIBRDP_SECURITY_AUTO;
    else if (strcmp(text, "standard") == 0)
        *mode = LIBRDP_SECURITY_STANDARD;
    else if (strcmp(text, "tls") == 0)
        *mode = LIBRDP_SECURITY_TLS;
    else if (strcmp(text, "nla") == 0)
        *mode = LIBRDP_SECURITY_NLA;
    else
        return 0;
    return 1;
}

static int require_value(int argc, int* index)
{
    if (*index + 1 >= argc)
        return 0;
    (*index)++;
    return 1;
}

static void app_event(librdp_session* session, const librdp_event* event, void* user_data)
{
    x11_app* app = (x11_app*)user_data;
    (void)session;

    if (!app || !event)
        return;

    switch (event->type)
    {
        case LIBRDP_EVENT_SURFACE_INVALIDATED:
            app->dirty = 1;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.active.framebuffer.blit",
                            "x=%u y=%u width=%u height=%u",
                            event->data.surface.x,
                            event->data.surface.y,
                            event->data.surface.width,
                            event->data.surface.height);
            break;
        case LIBRDP_EVENT_DISCONNECTED:
            app->running = 0;
            break;
        case LIBRDP_EVENT_ERROR:
            fprintf(stderr, "error=%s\n", librdp_status_string(event->data.error.status));
            app->running = 0;
            break;
        default:
            break;
    }
}

static void draw_surface(x11_app* app)
{
    const librdp_surface* surface = NULL;
    XImage* image = NULL;
    uint32_t width = 0;
    uint32_t height = 0;

    if (!app || !app->display || !app->session)
        return;

    surface = librdp_session_get_surface(app->session);
    if (!surface || !librdp_surface_pixels(surface))
        return;

    width = librdp_surface_width(surface);
    height = librdp_surface_height(surface);
    image = XCreateImage(app->display,
                         DefaultVisual(app->display, app->screen),
                         (unsigned)DefaultDepth(app->display, app->screen),
                         ZPixmap,
                         0,
                         (char*)librdp_surface_pixels(surface),
                         width,
                         height,
                         32,
                         (int)librdp_surface_stride(surface));
    if (!image)
        return;

    XPutImage(app->display, app->window, app->gc, image, 0, 0, 0, 0, width, height);
    image->data = NULL;
    XDestroyImage(image);
    XFlush(app->display);
    app->dirty = 0;
}

static void handle_key(x11_app* app, XKeyEvent* key, librdp_key_state state)
{
    librdp_key_event event;

    if (!app || !key)
        return;

    event.scancode = (uint32_t)(key->keycode & 0xffu);
    event.state = state;
    rdp_trace_event(RDP_TRACE_CLIENT, "x11.keyboard.key", "keycode=%u state=%u", event.scancode, (unsigned)state);
    (void)librdp_session_send_key(app->session, &event);
}

static void handle_button(x11_app* app, XButtonEvent* button, librdp_mouse_state state)
{
    librdp_mouse_event event;

    if (!app || !button)
        return;

    event.x = button->x < 0 ? 0 : (uint16_t)button->x;
    event.y = button->y < 0 ? 0 : (uint16_t)button->y;
    event.state = state;

    switch (button->button)
    {
        case Button1:
            event.button = LIBRDP_MOUSE_BUTTON_LEFT;
            break;
        case Button2:
            event.button = LIBRDP_MOUSE_BUTTON_MIDDLE;
            break;
        case Button3:
            event.button = LIBRDP_MOUSE_BUTTON_RIGHT;
            break;
        case Button4:
            event.button = LIBRDP_MOUSE_BUTTON_WHEEL_UP;
            break;
        case Button5:
            event.button = LIBRDP_MOUSE_BUTTON_WHEEL_DOWN;
            break;
        default:
            event.button = LIBRDP_MOUSE_BUTTON_NONE;
            break;
    }

    (void)librdp_session_send_mouse(app->session, &event);
}

static void handle_motion(x11_app* app, XMotionEvent* motion)
{
    librdp_mouse_event event;

    if (!app || !motion)
        return;

    event.x = motion->x < 0 ? 0 : (uint16_t)motion->x;
    event.y = motion->y < 0 ? 0 : (uint16_t)motion->y;
    event.button = LIBRDP_MOUSE_BUTTON_NONE;
    event.state = LIBRDP_MOUSE_MOVED;
    (void)librdp_session_send_mouse(app->session, &event);
}

static int configure_settings(librdp_settings* settings, int argc, char** argv)
{
    int i = 1;
    uint32_t width = librdp_settings_width(settings);
    uint32_t height = librdp_settings_height(settings);

    while (i < argc)
    {
        if (strcmp(argv[i], "--target") == 0)
        {
            if (!require_value(argc, &i) || librdp_settings_set_target(settings, argv[i]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--user") == 0)
        {
            if (!require_value(argc, &i) || librdp_settings_set_username(settings, argv[i]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--password") == 0)
        {
            if (!require_value(argc, &i) || librdp_settings_set_password(settings, argv[i]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--domain") == 0)
        {
            if (!require_value(argc, &i) || librdp_settings_set_domain(settings, argv[i]) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--port") == 0)
        {
            uint16_t port = 0;
            if (!require_value(argc, &i) || !parse_u16(argv[i], &port) ||
                librdp_settings_set_port(settings, port) != LIBRDP_STATUS_OK)
                return 0;
        }
        else if (strcmp(argv[i], "--width") == 0)
        {
            if (!require_value(argc, &i) || !parse_u32(argv[i], &width))
                return 0;
        }
        else if (strcmp(argv[i], "--height") == 0)
        {
            if (!require_value(argc, &i) || !parse_u32(argv[i], &height))
                return 0;
        }
        else if (strcmp(argv[i], "--security") == 0)
        {
            librdp_security_mode mode = LIBRDP_SECURITY_AUTO;
            if (!require_value(argc, &i) || !parse_security(argv[i], &mode) ||
                librdp_settings_set_security_mode(settings, mode) != LIBRDP_STATUS_OK)
                return 0;
        }
        else
        {
            return 0;
        }
        i++;
    }

    return librdp_settings_set_desktop_size(settings, width, height) == LIBRDP_STATUS_OK &&
           librdp_settings_target(settings) != NULL;
}

int main(int argc, char** argv)
{
    librdp_settings* settings = NULL;
    x11_app app;
    XEvent event;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t width = 0;
    uint32_t height = 0;

    memset(&app, 0, sizeof(app));
    settings = librdp_settings_new();
    if (!settings)
        return 1;

    if (!configure_settings(settings, argc, argv))
    {
        fprintf(stderr,
                "usage: %s --target host [--port port] [--user name] [--password value] [--domain name] [--width px] [--height px] [--security auto|standard|tls|nla]\n",
                argv[0]);
        librdp_settings_free(settings);
        return 2;
    }

    width = librdp_settings_width(settings);
    height = librdp_settings_height(settings);
    app.display = XOpenDisplay(NULL);
    if (!app.display)
    {
        fprintf(stderr, "error=x11_open_display\n");
        librdp_settings_free(settings);
        return 1;
    }

    app.screen = DefaultScreen(app.display);
    app.window = XCreateSimpleWindow(app.display,
                                     RootWindow(app.display, app.screen),
                                     0,
                                     0,
                                     width,
                                     height,
                                     0,
                                     BlackPixel(app.display, app.screen),
                                     BlackPixel(app.display, app.screen));
    app.gc = XCreateGC(app.display, app.window, 0, NULL);
    app.wm_delete = XInternAtom(app.display, "WM_DELETE_WINDOW", False);
    (void)XSetWMProtocols(app.display, app.window, &app.wm_delete, 1);
    XSelectInput(app.display,
                 app.window,
                 ExposureMask | KeyPressMask | KeyReleaseMask | ButtonPressMask | ButtonReleaseMask |
                     PointerMotionMask | StructureNotifyMask);
    XMapWindow(app.display, app.window);

    app.session = librdp_session_new(settings);
    librdp_settings_free(settings);
    if (!app.session)
    {
        XCloseDisplay(app.display);
        return 1;
    }

    librdp_session_set_event_callback(app.session, app_event, &app);
    status = librdp_session_connect(app.session);
    if (status != LIBRDP_STATUS_OK)
    {
        fprintf(stderr, "error=%s\n", librdp_status_string(status));
        librdp_session_free(app.session);
        XCloseDisplay(app.display);
        return 1;
    }

    app.running = 1;
    app.dirty = 1;
    while (app.running)
    {
        while (XPending(app.display) > 0)
        {
            XNextEvent(app.display, &event);
            if (event.type == Expose)
                app.dirty = 1;
            else if (event.type == ClientMessage && (Atom)event.xclient.data.l[0] == app.wm_delete)
                app.running = 0;
            else if (event.type == KeyPress)
                handle_key(&app, &event.xkey, LIBRDP_KEY_PRESSED);
            else if (event.type == KeyRelease)
                handle_key(&app, &event.xkey, LIBRDP_KEY_RELEASED);
            else if (event.type == ButtonPress)
                handle_button(&app, &event.xbutton, LIBRDP_MOUSE_PRESSED);
            else if (event.type == ButtonRelease)
                handle_button(&app, &event.xbutton, LIBRDP_MOUSE_RELEASED);
            else if (event.type == MotionNotify)
                handle_motion(&app, &event.xmotion);
            else if (event.type == ConfigureNotify && event.xconfigure.width > 0 && event.xconfigure.height > 0)
                (void)librdp_session_resize(app.session,
                                            (uint32_t)event.xconfigure.width,
                                            (uint32_t)event.xconfigure.height);
        }

        (void)librdp_session_run_once(app.session, 16);
        if (app.dirty)
            draw_surface(&app);
    }

    (void)librdp_session_disconnect(app.session);
    librdp_session_free(app.session);
    XFreeGC(app.display, app.gc);
    XDestroyWindow(app.display, app.window);
    XCloseDisplay(app.display);
    return 0;
}
