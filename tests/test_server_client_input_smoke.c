/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: end-to-end client input channel smoke tests.
 * Coverage: public client and server activation, server-initiated RDPEI
 * negotiation, touch and pen serialization, and remote wire decoding.
 * Bug classes: dropped DVC negotiation, contact-ID corruption, non-monotonic
 * timestamps, optional-field loss, malformed flags, and duplicate delivery.
 * Determinism: all transport stays on loopback and input is synthetic.
 */

#include "channels/core_input.h"
#include "channels/input_channel.h"

#include <librdp/librdp.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define INPUT_SMOKE_WIDTH LIBRDP_DESKTOP_MIN_DIMENSION
#define INPUT_SMOKE_HEIGHT LIBRDP_DESKTOP_MIN_DIMENSION
#define INPUT_SMOKE_CHANNEL_ID 41u
#define INPUT_SMOKE_PUMP_LIMIT 500u
#define INPUT_SMOKE_ENCODE_TIME 0x10203040u

typedef enum input_smoke_mode
{
    INPUT_SMOKE_TOUCH,
    INPUT_SMOKE_TOUCH_FALLBACK,
    INPUT_SMOKE_PEN,
    INPUT_SMOKE_CORE,
    INPUT_SMOKE_CORE_FALLBACK
} input_smoke_mode;

typedef struct input_smoke_fixture
{
    librdp_server_config config;
    pthread_t thread;
    atomic_uint port;
    atomic_uint stop;
    atomic_uint channel_open;
    atomic_uint client_ready;
    atomic_uint touch_received;
    atomic_uint pen_received;
    atomic_uint core_init_received;
    atomic_uint core_key_received;
    atomic_uint core_mouse_received;
    atomic_uint classic_key_received;
    atomic_uint classic_mouse_received;
    atomic_uint validation_errors;
    atomic_uint client_closed;
    input_smoke_mode mode;
    librdp_status status;
} input_smoke_fixture;

typedef struct input_smoke_client_state
{
    unsigned int active_events;
    unsigned int error_events;
    unsigned int trace_errors;
    unsigned int channel_ready;
    unsigned int touch_sent;
    unsigned int pen_sent;
    unsigned int core_ready;
    unsigned int key_sent;
    unsigned int mouse_sent;
    unsigned int core_key_sent;
    unsigned int core_mouse_sent;
    unsigned int slow_key_sent;
    unsigned int slow_mouse_sent;
} input_smoke_client_state;

static int input_smoke_check(int condition,
                             const char* expression,
                             int line)
{
    if (condition)
        return 0;
    fprintf(stderr,
            "test_server_client_input_smoke:%d: check failed: %s\n",
            line,
            expression);
    return 1;
}

#define REQUIRE(expression)                                             \
    do                                                                  \
    {                                                                   \
        if (input_smoke_check((expression), #expression, __LINE__) != 0) \
        {                                                               \
            result = 1;                                                 \
            goto cleanup;                                               \
        }                                                               \
    } while (0)

static int input_smoke_wait_for_port(const atomic_uint* source,
                                     uint16_t* port)
{
    const struct timespec delay = {0, 10000000L};
    unsigned int attempt = 0u;

    if (!source || !port)
        return 0;
    for (attempt = 0u; attempt < INPUT_SMOKE_PUMP_LIMIT; attempt++)
    {
        unsigned int value =
            atomic_load_explicit(source, memory_order_acquire);

        if (value > 0u && value <= UINT16_MAX)
        {
            *port = (uint16_t)value;
            return 1;
        }
        (void)nanosleep(&delay, NULL);
    }
    return 0;
}

static librdp_status input_smoke_accept_active(
    librdp_server* server,
    const atomic_uint* stop,
    librdp_server_peer** peer)
{
    unsigned int attempt = 0u;
    librdp_status status = LIBRDP_STATUS_TIMEOUT;

    if (!server || !stop || !peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *peer = NULL;
    for (attempt = 0u;
         attempt < INPUT_SMOKE_PUMP_LIMIT &&
         atomic_load_explicit(stop, memory_order_acquire) == 0u &&
         !*peer;
         attempt++)
    {
        status = librdp_server_accept(server, 20, peer);
        if (status == LIBRDP_STATUS_TIMEOUT)
            continue;
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (!*peer)
        return atomic_load_explicit(stop, memory_order_acquire) != 0u
                   ? LIBRDP_STATUS_CANCELLED
                   : LIBRDP_STATUS_TIMEOUT;
    for (attempt = 0u;
         attempt < INPUT_SMOKE_PUMP_LIMIT &&
         atomic_load_explicit(stop, memory_order_acquire) == 0u;
         attempt++)
    {
        if (librdp_server_peer_get_state(*peer) ==
            LIBRDP_SERVER_PEER_ACTIVE)
            return LIBRDP_STATUS_OK;
        status = librdp_server_peer_run_once(*peer, 20);
        if (status != LIBRDP_STATUS_OK &&
            status != LIBRDP_STATUS_TIMEOUT)
            return status;
    }
    return atomic_load_explicit(stop, memory_order_acquire) != 0u
               ? LIBRDP_STATUS_CANCELLED
               : LIBRDP_STATUS_TIMEOUT;
}

static int input_smoke_touch_contact_matches(
    const rdp_input_channel_touch_contact* contact,
    uint8_t contact_id,
    uint16_t fields_present,
    int32_t x,
    int32_t y,
    uint32_t contact_flags,
    int16_t rect_left,
    int16_t rect_top,
    int16_t rect_right,
    int16_t rect_bottom,
    uint32_t orientation,
    uint32_t pressure)
{
    return contact &&
           contact->contact_id == contact_id &&
           contact->fields_present == fields_present &&
           contact->x == x &&
           contact->y == y &&
           contact->contact_flags == contact_flags &&
           contact->contact_rect_left == rect_left &&
           contact->contact_rect_top == rect_top &&
           contact->contact_rect_right == rect_right &&
           contact->contact_rect_bottom == rect_bottom &&
           contact->orientation == orientation &&
           contact->pressure == pressure;
}

/*
 * Decode the received touch PDU independently of the client-side serializer.
 * Exact field checks make the smoke sensitive to wire-order and optional-field
 * regressions rather than merely accepting any syntactically valid message.
 */
static int input_smoke_touch_event_matches(const uint8_t* data,
                                           size_t data_len)
{
    rdp_input_channel_touch_event event;
    rdp_input_channel_touch_frame frame;
    rdp_input_channel_touch_contact contact;
    uint64_t previous_offset = 0u;
    uint16_t frame_index = 0u;

    if (rdp_input_channel_parse_touch_event(data,
                                            data_len,
                                            &event) !=
            LIBRDP_STATUS_OK ||
        event.encode_time != INPUT_SMOKE_ENCODE_TIME ||
        event.frame_count != 3u)
        return 0;
    for (frame_index = 0u;
         frame_index < event.frame_count;
         frame_index++)
    {
        if (rdp_input_channel_touch_event_get_frame(
                &event,
                frame_index,
                &frame) != LIBRDP_STATUS_OK ||
            frame.contact_count != 2u ||
            frame.frame_offset <= previous_offset)
            return 0;
        previous_offset = frame.frame_offset;
        if (frame.frame_offset !=
            (uint64_t)(frame_index + 1u) * 100u)
            return 0;

        if (rdp_input_channel_touch_frame_get_contact(
                &frame,
                0u,
                &contact) != LIBRDP_STATUS_OK)
            return 0;
        if (frame_index == 0u)
        {
            if (!input_smoke_touch_contact_matches(
                    &contact,
                    1u,
                    LIBRDP_TOUCH_CONTACTRECT_PRESENT |
                        LIBRDP_TOUCH_ORIENTATION_PRESENT |
                        LIBRDP_TOUCH_PRESSURE_PRESENT,
                    100,
                    120,
                    LIBRDP_CONTACT_DOWN |
                        LIBRDP_CONTACT_INRANGE |
                        LIBRDP_CONTACT_INCONTACT,
                    -4,
                    -5,
                    4,
                    5,
                    45u,
                    600u))
                return 0;
        }
        else if (frame_index == 1u)
        {
            if (!input_smoke_touch_contact_matches(
                    &contact,
                    1u,
                    LIBRDP_TOUCH_CONTACTRECT_PRESENT |
                        LIBRDP_TOUCH_ORIENTATION_PRESENT |
                        LIBRDP_TOUCH_PRESSURE_PRESENT,
                    110,
                    130,
                    LIBRDP_CONTACT_UPDATE |
                        LIBRDP_CONTACT_INRANGE |
                        LIBRDP_CONTACT_INCONTACT,
                    -3,
                    -4,
                    5,
                    6,
                    50u,
                    650u))
                return 0;
        }
        else if (!input_smoke_touch_contact_matches(
                     &contact,
                     1u,
                     0u,
                     110,
                     130,
                     LIBRDP_CONTACT_UP |
                         LIBRDP_CONTACT_INRANGE,
                     0,
                     0,
                     0,
                     0,
                     0u,
                     0u))
            return 0;

        if (rdp_input_channel_touch_frame_get_contact(
                &frame,
                1u,
                &contact) != LIBRDP_STATUS_OK)
            return 0;
        if (frame_index == 0u)
        {
            if (!input_smoke_touch_contact_matches(
                    &contact,
                    2u,
                    LIBRDP_TOUCH_PRESSURE_PRESENT,
                    300,
                    320,
                    LIBRDP_CONTACT_DOWN |
                        LIBRDP_CONTACT_INRANGE |
                        LIBRDP_CONTACT_INCONTACT,
                    0,
                    0,
                    0,
                    0,
                    0u,
                    700u))
                return 0;
        }
        else if (frame_index == 1u)
        {
            if (!input_smoke_touch_contact_matches(
                    &contact,
                    2u,
                    LIBRDP_TOUCH_PRESSURE_PRESENT,
                    310,
                    330,
                    LIBRDP_CONTACT_UPDATE |
                        LIBRDP_CONTACT_INRANGE |
                        LIBRDP_CONTACT_INCONTACT,
                    0,
                    0,
                    0,
                    0,
                    0u,
                    720u))
                return 0;
        }
        else if (!input_smoke_touch_contact_matches(
                     &contact,
                     2u,
                     0u,
                     310,
                     330,
                     LIBRDP_CONTACT_UP |
                         LIBRDP_CONTACT_CANCELED,
                     0,
                     0,
                     0,
                     0,
                     0u,
                     0u))
            return 0;
    }
    return 1;
}

static int input_smoke_pen_contact_matches(
    const rdp_input_channel_pen_contact* contact,
    uint8_t device_id,
    uint16_t fields_present,
    int32_t x,
    int32_t y,
    uint32_t contact_flags,
    uint32_t pen_flags,
    uint32_t pressure,
    uint16_t rotation,
    int16_t tilt_x,
    int16_t tilt_y)
{
    return contact &&
           contact->device_id == device_id &&
           contact->fields_present == fields_present &&
           contact->x == x &&
           contact->y == y &&
           contact->contact_flags == contact_flags &&
           contact->pen_flags == pen_flags &&
           contact->pressure == pressure &&
           contact->rotation == rotation &&
           contact->tilt_x == tilt_x &&
           contact->tilt_y == tilt_y;
}

/*
 * Check the public pen API at the receiver's protocol boundary. The sequence
 * covers hover, contact, button state, and the inclusive limits for pressure,
 * rotation, and tilt without relying on the sender's in-memory structures.
 */
static int input_smoke_pen_event_matches(const uint8_t* data,
                                         size_t data_len)
{
    static const uint32_t flags[4] = {
        LIBRDP_CONTACT_UPDATE | LIBRDP_CONTACT_INRANGE,
        LIBRDP_CONTACT_DOWN | LIBRDP_CONTACT_INRANGE |
            LIBRDP_CONTACT_INCONTACT,
        LIBRDP_CONTACT_UPDATE | LIBRDP_CONTACT_INRANGE |
            LIBRDP_CONTACT_INCONTACT,
        LIBRDP_CONTACT_UP | LIBRDP_CONTACT_INRANGE};
    static const int32_t x[4] = {40, 42, 44, 44};
    static const int32_t y[4] = {50, 52, 54, 54};
    static const uint32_t pen_flags[4] = {
        0u,
        LIBRDP_PEN_BARREL_PRESSED,
        LIBRDP_PEN_ERASER_PRESSED | LIBRDP_PEN_INVERTED,
        0u};
    static const uint32_t pressure[4] = {0u, 512u, 1024u, 0u};
    static const uint16_t rotation[4] = {10u, 90u, 359u, 0u};
    static const int16_t tilt_x[4] = {-5, -20, 90, 0};
    static const int16_t tilt_y[4] = {6, 30, -90, 0};
    const uint16_t all_fields =
        LIBRDP_PEN_FLAGS_PRESENT |
        LIBRDP_PEN_PRESSURE_PRESENT |
        LIBRDP_PEN_ROTATION_PRESENT |
        LIBRDP_PEN_TILTX_PRESENT |
        LIBRDP_PEN_TILTY_PRESENT;
    rdp_input_channel_pen_event event;
    uint16_t frame_index = 0u;

    if (rdp_input_channel_parse_pen_event(data,
                                          data_len,
                                          &event) !=
            LIBRDP_STATUS_OK ||
        event.encode_time != INPUT_SMOKE_ENCODE_TIME ||
        event.frame_count != 4u)
        return 0;
    for (frame_index = 0u;
         frame_index < event.frame_count;
         frame_index++)
    {
        rdp_input_channel_pen_frame frame;
        rdp_input_channel_pen_contact contact;
        uint16_t fields_present =
            frame_index < 3u ? all_fields : 0u;

        if (rdp_input_channel_pen_event_get_frame(
                &event,
                frame_index,
                &frame) != LIBRDP_STATUS_OK ||
            frame.contact_count != 1u ||
            frame.frame_offset !=
                (uint64_t)(frame_index + 1u) * 50u ||
            rdp_input_channel_pen_frame_get_contact(
                &frame,
                0u,
                &contact) != LIBRDP_STATUS_OK ||
            !input_smoke_pen_contact_matches(
                &contact,
                7u,
                fields_present,
                x[frame_index],
                y[frame_index],
                flags[frame_index],
                pen_flags[frame_index],
                pressure[frame_index],
                rotation[frame_index],
                tilt_x[frame_index],
                tilt_y[frame_index]))
            return 0;
    }
    return 1;
}

static void input_smoke_server_core_channel(
    const librdp_server_channel_event* event,
    input_smoke_fixture* fixture)
{
    rdp_core_input_header header;

    if (!event || !fixture || !event->data ||
        rdp_core_input_parse_header(event->data,
                                    event->data_len,
                                    &header) != LIBRDP_STATUS_OK)
    {
        atomic_fetch_add_explicit(&fixture->validation_errors,
                                  1u,
                                  memory_order_release);
        return;
    }
    if (header.pdu_type == RDP_CORE_INPUT_PDU_CS_INIT_REQUEST)
    {
        rdp_core_input_init_request request;

        if (rdp_core_input_parse_init_request(event->data,
                                              event->data_len,
                                              &request) !=
                LIBRDP_STATUS_OK ||
            request.protocol_version_min !=
                RDP_CORE_INPUT_PROTOCOL_VERSION_100 ||
            request.protocol_version_max !=
                RDP_CORE_INPUT_PROTOCOL_VERSION_100)
        {
            atomic_fetch_add_explicit(
                &fixture->validation_errors,
                1u,
                memory_order_release);
            return;
        }
        atomic_fetch_add_explicit(&fixture->core_init_received,
                                  1u,
                                  memory_order_release);
        return;
    }
    if (header.pdu_type ==
        RDP_CORE_INPUT_PDU_CS_KEYBOARD_AND_MOUSE)
    {
        rdp_core_input_event events[2];
        uint8_t event_count = 0u;

        if (rdp_core_input_parse_events(event->data,
                                        event->data_len,
                                        events,
                                        2u,
                                        &event_count) !=
                LIBRDP_STATUS_OK ||
            event_count != 1u)
        {
            atomic_fetch_add_explicit(
                &fixture->validation_errors,
                1u,
                memory_order_release);
            return;
        }
        if (events[0].type == RDP_CORE_INPUT_EVENT_SCANCODE &&
            events[0].flags == 0u &&
            events[0].scancode == 0x1eu)
        {
            atomic_fetch_add_explicit(
                &fixture->core_key_received,
                1u,
                memory_order_release);
            return;
        }
        if (events[0].type == RDP_CORE_INPUT_EVENT_MOUSE &&
            events[0].flags == 0u &&
            events[0].pointer_flags == 0x0800u &&
            events[0].x == 17u &&
            events[0].y == 19u)
        {
            atomic_fetch_add_explicit(
                &fixture->core_mouse_received,
                1u,
                memory_order_release);
            return;
        }
    }
    atomic_fetch_add_explicit(&fixture->validation_errors,
                              1u,
                              memory_order_release);
}

static void input_smoke_server_channel(
    librdp_server_peer* peer,
    const librdp_server_channel_event* event,
    void* user_data)
{
    input_smoke_fixture* fixture =
        (input_smoke_fixture*)user_data;
    rdp_input_channel_header header;

    (void)peer;
    if (!fixture || !event ||
        event->dynamic_channel_id != INPUT_SMOKE_CHANNEL_ID)
        return;
    if (event->type == LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_OPEN)
    {
        atomic_fetch_add_explicit(&fixture->channel_open,
                                  1u,
                                  memory_order_release);
        return;
    }
    if (fixture->mode == INPUT_SMOKE_CORE)
    {
        if (event->type !=
            LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_DATA)
        {
            atomic_fetch_add_explicit(
                &fixture->validation_errors,
                1u,
                memory_order_release);
            return;
        }
        input_smoke_server_core_channel(event, fixture);
        return;
    }
    if (event->type != LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_DATA ||
        !event->data ||
        rdp_input_channel_parse_header(event->data,
                                       event->data_len,
                                       &header) !=
            LIBRDP_STATUS_OK)
    {
        atomic_fetch_add_explicit(&fixture->validation_errors,
                                  1u,
                                  memory_order_release);
        return;
    }
    if (header.event_id == RDP_INPUT_CHANNEL_EVENT_CS_READY)
    {
        rdp_input_channel_cs_ready ready;

        if (rdp_input_channel_parse_cs_ready(event->data,
                                             event->data_len,
                                             &ready) !=
                LIBRDP_STATUS_OK ||
            ready.protocol_version !=
                RDP_INPUT_CHANNEL_PROTOCOL_V300 ||
            ready.max_touch_contacts != 10u ||
            (ready.flags &
             (RDP_INPUT_CHANNEL_CS_DISABLE_TIMESTAMP_INJECTION |
              RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN)) !=
                (RDP_INPUT_CHANNEL_CS_DISABLE_TIMESTAMP_INJECTION |
                 RDP_INPUT_CHANNEL_CS_ENABLE_MULTIPEN))
        {
            atomic_fetch_add_explicit(
                &fixture->validation_errors,
                1u,
                memory_order_release);
            return;
        }
        atomic_fetch_add_explicit(&fixture->client_ready,
                                  1u,
                                  memory_order_release);
    }
    else if (header.event_id == RDP_INPUT_CHANNEL_EVENT_TOUCH)
    {
        if (fixture->mode != INPUT_SMOKE_TOUCH ||
            !input_smoke_touch_event_matches(event->data,
                                             event->data_len))
        {
            atomic_fetch_add_explicit(
                &fixture->validation_errors,
                1u,
                memory_order_release);
            return;
        }
        atomic_fetch_add_explicit(&fixture->touch_received,
                                  1u,
                                  memory_order_release);
    }
    else if (header.event_id == RDP_INPUT_CHANNEL_EVENT_PEN)
    {
        if (fixture->mode != INPUT_SMOKE_PEN ||
            !input_smoke_pen_event_matches(event->data,
                                           event->data_len))
        {
            atomic_fetch_add_explicit(
                &fixture->validation_errors,
                1u,
                memory_order_release);
            return;
        }
        atomic_fetch_add_explicit(&fixture->pen_received,
                                  1u,
                                  memory_order_release);
    }
    else
    {
        atomic_fetch_add_explicit(&fixture->validation_errors,
                                  1u,
                                  memory_order_release);
    }
}

static void input_smoke_server_input(
    librdp_server_peer* peer,
    const librdp_server_input_event* event,
    void* user_data)
{
    input_smoke_fixture* fixture =
        (input_smoke_fixture*)user_data;

    (void)peer;
    if (!fixture || !event)
        return;
    if (event->type == LIBRDP_SERVER_INPUT_SCANCODE_KEY)
    {
        if (event->flags == 0u &&
            event->param1 == 0x1eu)
            atomic_fetch_add_explicit(
                &fixture->classic_key_received,
                1u,
                memory_order_release);
        else
            atomic_fetch_add_explicit(
                &fixture->validation_errors,
                1u,
                memory_order_release);
    }
    else if (event->type == LIBRDP_SERVER_INPUT_MOUSE)
    {
        if (event->flags == 0x0800u &&
            event->x == 17u &&
            event->y == 19u)
            atomic_fetch_add_explicit(
                &fixture->classic_mouse_received,
                1u,
                memory_order_release);
        else
            atomic_fetch_add_explicit(
                &fixture->validation_errors,
                1u,
                memory_order_release);
    }
}

static int input_smoke_server_received_expected(
    const input_smoke_fixture* fixture)
{
    const unsigned int touch =
        atomic_load_explicit(&fixture->touch_received,
                             memory_order_acquire);
    const unsigned int pen =
        atomic_load_explicit(&fixture->pen_received,
                             memory_order_acquire);
    const unsigned int core_init =
        atomic_load_explicit(&fixture->core_init_received,
                             memory_order_acquire);
    const unsigned int core_key =
        atomic_load_explicit(&fixture->core_key_received,
                             memory_order_acquire);
    const unsigned int core_mouse =
        atomic_load_explicit(&fixture->core_mouse_received,
                             memory_order_acquire);
    const unsigned int classic_key =
        atomic_load_explicit(&fixture->classic_key_received,
                             memory_order_acquire);
    const unsigned int classic_mouse =
        atomic_load_explicit(&fixture->classic_mouse_received,
                             memory_order_acquire);

    if (fixture->mode == INPUT_SMOKE_TOUCH)
        return touch == 1u && pen == 0u &&
               core_init == 0u && core_key == 0u &&
               core_mouse == 0u && classic_key == 0u &&
               classic_mouse == 0u;
    if (fixture->mode == INPUT_SMOKE_PEN)
        return touch == 0u && pen == 1u &&
               core_init == 0u && core_key == 0u &&
               core_mouse == 0u && classic_key == 0u &&
               classic_mouse == 0u;
    if (fixture->mode == INPUT_SMOKE_TOUCH_FALLBACK)
        return touch == 0u && pen == 0u &&
               core_init == 0u && core_key == 0u &&
               core_mouse == 0u && classic_key == 0u &&
               classic_mouse == 1u;
    if (fixture->mode == INPUT_SMOKE_CORE)
        return touch == 0u && pen == 0u &&
               core_init == 1u && core_key == 1u &&
               core_mouse == 1u && classic_key == 0u &&
               classic_mouse == 0u;
    return touch == 0u && pen == 0u &&
           core_init == 0u && core_key == 0u &&
           core_mouse == 0u && classic_key == 1u &&
           classic_mouse == 1u;
}

static void* input_smoke_server_main(void* user_data)
{
    input_smoke_fixture* fixture =
        (input_smoke_fixture*)user_data;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    unsigned int attempt = 0u;

    if (!fixture)
        return NULL;
    fixture->status = LIBRDP_STATUS_NO_MEMORY;
    server = librdp_server_new(&fixture->config);
    if (!server)
        return NULL;
    fixture->status = librdp_server_listen(server);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    atomic_store_explicit(&fixture->port,
                          librdp_server_local_port(server),
                          memory_order_release);
    fixture->status = input_smoke_accept_active(
        server,
        &fixture->stop,
        &peer);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    fixture->status = librdp_server_peer_set_channel_callback(
        peer,
        input_smoke_server_channel,
        fixture);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    fixture->status = librdp_server_peer_set_input_callback(
        peer,
        input_smoke_server_input,
        fixture);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    if (fixture->mode == INPUT_SMOKE_TOUCH ||
        fixture->mode == INPUT_SMOKE_PEN ||
        fixture->mode == INPUT_SMOKE_CORE)
    {
        const char* channel_name =
            fixture->mode == INPUT_SMOKE_CORE
                ? RDP_CORE_INPUT_CHANNEL_NAME
                : RDP_INPUT_CHANNEL_NAME;

        for (attempt = 0u;
             attempt < INPUT_SMOKE_PUMP_LIMIT &&
             atomic_load_explicit(&fixture->stop,
                                  memory_order_acquire) == 0u;
             attempt++)
        {
            fixture->status =
                librdp_server_peer_open_dynamic_channel(
                    peer,
                    INPUT_SMOKE_CHANNEL_ID,
                    0u,
                    channel_name);
            if (fixture->status == LIBRDP_STATUS_OK)
                break;
            if (fixture->status != LIBRDP_STATUS_STATE)
                goto cleanup;
            fixture->status =
                librdp_server_peer_run_once(peer, 20);
            if (fixture->status != LIBRDP_STATUS_OK &&
                fixture->status != LIBRDP_STATUS_TIMEOUT)
                goto cleanup;
        }
        if (attempt == INPUT_SMOKE_PUMP_LIMIT)
        {
            fixture->status = LIBRDP_STATUS_TIMEOUT;
            goto cleanup;
        }
        for (attempt = 0u;
             attempt < INPUT_SMOKE_PUMP_LIMIT &&
             atomic_load_explicit(&fixture->channel_open,
                                  memory_order_acquire) == 0u &&
             atomic_load_explicit(&fixture->stop,
                                  memory_order_acquire) == 0u;
             attempt++)
        {
            fixture->status =
                librdp_server_peer_run_once(peer, 20);
            if (fixture->status != LIBRDP_STATUS_OK &&
                fixture->status != LIBRDP_STATUS_TIMEOUT)
                goto cleanup;
        }
        if (atomic_load_explicit(&fixture->channel_open,
                                 memory_order_acquire) != 1u)
        {
            fixture->status = LIBRDP_STATUS_TIMEOUT;
            goto cleanup;
        }
        if (fixture->mode == INPUT_SMOKE_CORE)
        {
            for (attempt = 0u;
                 attempt < INPUT_SMOKE_PUMP_LIMIT &&
                 atomic_load_explicit(
                     &fixture->core_init_received,
                     memory_order_acquire) == 0u &&
                 atomic_load_explicit(&fixture->stop,
                                      memory_order_acquire) == 0u;
                 attempt++)
            {
                fixture->status =
                    librdp_server_peer_run_once(peer, 20);
                if (fixture->status != LIBRDP_STATUS_OK &&
                    fixture->status != LIBRDP_STATUS_TIMEOUT)
                    goto cleanup;
            }
            if (atomic_load_explicit(
                    &fixture->core_init_received,
                    memory_order_acquire) != 1u)
            {
                fixture->status = LIBRDP_STATUS_TIMEOUT;
                goto cleanup;
            }
            fixture->status =
                librdp_server_peer_send_core_input_init(
                    peer,
                    INPUT_SMOKE_CHANNEL_ID);
        }
        else
        {
            fixture->status =
                librdp_server_peer_send_touch_ready(
                    peer,
                    INPUT_SMOKE_CHANNEL_ID,
                    RDP_INPUT_CHANNEL_PROTOCOL_V300,
                    RDP_INPUT_CHANNEL_SC_READY_MULTIPEN,
                    1);
        }
        if (fixture->status != LIBRDP_STATUS_OK)
            goto cleanup;
    }

    fixture->status = LIBRDP_STATUS_TIMEOUT;
    for (attempt = 0u;
         attempt < INPUT_SMOKE_PUMP_LIMIT &&
         atomic_load_explicit(&fixture->stop,
                              memory_order_acquire) == 0u;
         attempt++)
    {
        librdp_status status =
            librdp_server_peer_run_once(peer, 20);

        if (status == LIBRDP_STATUS_CLOSED ||
            status == LIBRDP_STATUS_IO_ERROR)
        {
            atomic_store_explicit(&fixture->client_closed,
                                  1u,
                                  memory_order_release);
            fixture->status =
                input_smoke_server_received_expected(fixture) &&
                        atomic_load_explicit(&fixture->validation_errors,
                                             memory_order_acquire) == 0u
                    ? LIBRDP_STATUS_OK
                    : LIBRDP_STATUS_PROTOCOL_ERROR;
            break;
        }
        if (status != LIBRDP_STATUS_OK &&
            status != LIBRDP_STATUS_TIMEOUT)
        {
            fixture->status = status;
            break;
        }
    }

cleanup:
    if (peer)
    {
        (void)librdp_server_peer_close(peer);
        librdp_server_peer_free(peer);
    }
    if (server)
    {
        (void)librdp_server_close(server);
        librdp_server_free(server);
    }
    return NULL;
}

static void input_smoke_client_event(librdp_session* session,
                                     const librdp_event* event,
                                     void* user_data)
{
    input_smoke_client_state* state =
        (input_smoke_client_state*)user_data;

    (void)session;
    if (!state || !event)
        return;
    if (event->type == LIBRDP_EVENT_STATE_CHANGED &&
        event->data.state.new_state == LIBRDP_SESSION_ACTIVE)
        state->active_events++;
    else if (event->type == LIBRDP_EVENT_ERROR)
        state->error_events++;
}

static void input_smoke_trace(librdp_session* session,
                              const librdp_trace_record* record,
                              void* user_data)
{
    input_smoke_client_state* state =
        (input_smoke_client_state*)user_data;

    (void)session;
    if (!state || !record)
        return;
    if (getenv("LIBRDP_SMOKE_TRACE_OUTPUT") && record->line)
        fprintf(stderr, "%s\n", record->line);
    if (record->level &&
        strcmp(record->level, "error") == 0)
        state->trace_errors++;
    if (record->event &&
        record->level &&
        strcmp(record->level, "info") == 0 &&
        strcmp(record->event,
               "client.input_channel.ready") == 0)
        state->channel_ready++;
    else if (record->event &&
             record->level &&
             strcmp(record->level, "info") == 0 &&
             strcmp(record->event,
                    "client.core_input.ready") == 0)
        state->core_ready++;
    else if (record->event &&
             strcmp(record->event,
                    "client.input_channel.touch_send") == 0)
        state->touch_sent++;
    else if (record->event &&
             strcmp(record->event,
                    "client.input_channel.pen_send") == 0)
        state->pen_sent++;
    else if (record->event &&
             record->level &&
             strcmp(record->level, "info") == 0 &&
             strcmp(record->event,
                    "client.input.send") == 0 &&
             record->message)
    {
        if (strstr(record->message,
                   "kind=keyboard ") != NULL)
        {
            state->key_sent++;
            if (strstr(record->message,
                       "transport=core_input ") != NULL)
                state->core_key_sent++;
            else if (strstr(record->message,
                            "transport=slowpath ") != NULL)
                state->slow_key_sent++;
        }
        else if (strstr(record->message,
                        "kind=mouse ") != NULL)
        {
            state->mouse_sent++;
            if (strstr(record->message,
                       "transport=core_input ") != NULL)
                state->core_mouse_sent++;
            else if (strstr(record->message,
                            "transport=slowpath ") != NULL)
                state->slow_mouse_sent++;
        }
    }
}

static void input_smoke_prepare_touch(
    librdp_touch_frame frames[3],
    librdp_touch_contact contacts[3][2])
{
    memset(frames, 0, sizeof(*frames) * 3u);
    memset(contacts, 0, sizeof(*contacts) * 3u);

    contacts[0][0].contact_id = 1u;
    contacts[0][0].fields_present =
        LIBRDP_TOUCH_CONTACTRECT_PRESENT |
        LIBRDP_TOUCH_ORIENTATION_PRESENT |
        LIBRDP_TOUCH_PRESSURE_PRESENT;
    contacts[0][0].x = 100;
    contacts[0][0].y = 120;
    contacts[0][0].contact_flags =
        LIBRDP_CONTACT_DOWN |
        LIBRDP_CONTACT_INRANGE |
        LIBRDP_CONTACT_INCONTACT;
    contacts[0][0].contact_rect_left = -4;
    contacts[0][0].contact_rect_top = -5;
    contacts[0][0].contact_rect_right = 4;
    contacts[0][0].contact_rect_bottom = 5;
    contacts[0][0].orientation = 45u;
    contacts[0][0].pressure = 600u;
    contacts[0][1].contact_id = 2u;
    contacts[0][1].fields_present =
        LIBRDP_TOUCH_PRESSURE_PRESENT;
    contacts[0][1].x = 300;
    contacts[0][1].y = 320;
    contacts[0][1].contact_flags =
        LIBRDP_CONTACT_DOWN |
        LIBRDP_CONTACT_INRANGE |
        LIBRDP_CONTACT_INCONTACT;
    contacts[0][1].pressure = 700u;

    contacts[1][0] = contacts[0][0];
    contacts[1][0].x = 110;
    contacts[1][0].y = 130;
    contacts[1][0].contact_flags =
        LIBRDP_CONTACT_UPDATE |
        LIBRDP_CONTACT_INRANGE |
        LIBRDP_CONTACT_INCONTACT;
    contacts[1][0].contact_rect_left = -3;
    contacts[1][0].contact_rect_top = -4;
    contacts[1][0].contact_rect_right = 5;
    contacts[1][0].contact_rect_bottom = 6;
    contacts[1][0].orientation = 50u;
    contacts[1][0].pressure = 650u;
    contacts[1][1] = contacts[0][1];
    contacts[1][1].x = 310;
    contacts[1][1].y = 330;
    contacts[1][1].contact_flags =
        LIBRDP_CONTACT_UPDATE |
        LIBRDP_CONTACT_INRANGE |
        LIBRDP_CONTACT_INCONTACT;
    contacts[1][1].pressure = 720u;

    contacts[2][0].contact_id = 1u;
    contacts[2][0].x = 110;
    contacts[2][0].y = 130;
    contacts[2][0].contact_flags =
        LIBRDP_CONTACT_UP |
        LIBRDP_CONTACT_INRANGE;
    contacts[2][1].contact_id = 2u;
    contacts[2][1].x = 310;
    contacts[2][1].y = 330;
    contacts[2][1].contact_flags =
        LIBRDP_CONTACT_UP |
        LIBRDP_CONTACT_CANCELED;

    frames[0].contact_count = 2u;
    frames[0].frame_offset = 100u;
    frames[0].contacts = contacts[0];
    frames[1].contact_count = 2u;
    frames[1].frame_offset = 200u;
    frames[1].contacts = contacts[1];
    frames[2].contact_count = 2u;
    frames[2].frame_offset = 300u;
    frames[2].contacts = contacts[2];
}

static void input_smoke_prepare_pen(
    librdp_pen_frame frames[4],
    librdp_pen_contact contacts[4])
{
    const uint16_t all_fields =
        LIBRDP_PEN_FLAGS_PRESENT |
        LIBRDP_PEN_PRESSURE_PRESENT |
        LIBRDP_PEN_ROTATION_PRESENT |
        LIBRDP_PEN_TILTX_PRESENT |
        LIBRDP_PEN_TILTY_PRESENT;
    unsigned int index = 0u;

    memset(frames, 0, sizeof(*frames) * 4u);
    memset(contacts, 0, sizeof(*contacts) * 4u);
    contacts[0].device_id = 7u;
    contacts[0].fields_present = all_fields;
    contacts[0].x = 40;
    contacts[0].y = 50;
    contacts[0].contact_flags =
        LIBRDP_CONTACT_UPDATE | LIBRDP_CONTACT_INRANGE;
    contacts[0].rotation = 10u;
    contacts[0].tilt_x = -5;
    contacts[0].tilt_y = 6;

    contacts[1] = contacts[0];
    contacts[1].x = 42;
    contacts[1].y = 52;
    contacts[1].contact_flags =
        LIBRDP_CONTACT_DOWN |
        LIBRDP_CONTACT_INRANGE |
        LIBRDP_CONTACT_INCONTACT;
    contacts[1].pen_flags = LIBRDP_PEN_BARREL_PRESSED;
    contacts[1].pressure = 512u;
    contacts[1].rotation = 90u;
    contacts[1].tilt_x = -20;
    contacts[1].tilt_y = 30;

    contacts[2] = contacts[1];
    contacts[2].x = 44;
    contacts[2].y = 54;
    contacts[2].contact_flags =
        LIBRDP_CONTACT_UPDATE |
        LIBRDP_CONTACT_INRANGE |
        LIBRDP_CONTACT_INCONTACT;
    contacts[2].pen_flags =
        LIBRDP_PEN_ERASER_PRESSED |
        LIBRDP_PEN_INVERTED;
    contacts[2].pressure = 1024u;
    contacts[2].rotation = 359u;
    contacts[2].tilt_x = 90;
    contacts[2].tilt_y = -90;

    contacts[3].device_id = 7u;
    contacts[3].x = 44;
    contacts[3].y = 54;
    contacts[3].contact_flags =
        LIBRDP_CONTACT_UP | LIBRDP_CONTACT_INRANGE;
    for (index = 0u; index < 4u; index++)
    {
        frames[index].contact_count = 1u;
        frames[index].frame_offset =
            (uint64_t)(index + 1u) * 50u;
        frames[index].contacts = &contacts[index];
    }
}

static int input_smoke_run(input_smoke_mode mode)
{
    input_smoke_fixture fixture;
    input_smoke_client_state state;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_trace_policy trace_policy;
    librdp_touch_frame frames[3];
    librdp_touch_contact contacts[3][2];
    librdp_pen_frame pen_frames[4];
    librdp_pen_contact pen_contacts[4];
    librdp_key_event key;
    librdp_mouse_event mouse;
    uint16_t port = 0u;
    unsigned int attempt = 0u;
    int sent = 0;
    int thread_started = 0;
    int result = 1;

    memset(&fixture, 0, sizeof(fixture));
    memset(&state, 0, sizeof(state));
    memset(&key, 0, sizeof(key));
    memset(&mouse, 0, sizeof(mouse));
    atomic_init(&fixture.port, 0u);
    atomic_init(&fixture.stop, 0u);
    atomic_init(&fixture.channel_open, 0u);
    atomic_init(&fixture.client_ready, 0u);
    atomic_init(&fixture.touch_received, 0u);
    atomic_init(&fixture.pen_received, 0u);
    atomic_init(&fixture.core_init_received, 0u);
    atomic_init(&fixture.core_key_received, 0u);
    atomic_init(&fixture.core_mouse_received, 0u);
    atomic_init(&fixture.classic_key_received, 0u);
    atomic_init(&fixture.classic_mouse_received, 0u);
    atomic_init(&fixture.validation_errors, 0u);
    atomic_init(&fixture.client_closed, 0u);
    fixture.mode = mode;
    fixture.status = LIBRDP_STATUS_AGAIN;
    REQUIRE(librdp_server_config_init(&fixture.config) ==
            LIBRDP_STATUS_OK);
    fixture.config.bind_address = "127.0.0.1";
    fixture.config.security_mode = LIBRDP_SECURITY_STANDARD;
    fixture.config.width = INPUT_SMOKE_WIDTH;
    fixture.config.height = INPUT_SMOKE_HEIGHT;
    REQUIRE(pthread_create(&fixture.thread,
                           NULL,
                           input_smoke_server_main,
                           &fixture) == 0);
    thread_started = 1;
    REQUIRE(input_smoke_wait_for_port(&fixture.port, &port));

    settings = librdp_settings_new();
    REQUIRE(settings != NULL);
    REQUIRE(librdp_settings_set_target(settings,
                                       "127.0.0.1") ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_port(settings, port) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_security_mode(
                settings,
                LIBRDP_SECURITY_STANDARD) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_desktop_size(
                settings,
                INPUT_SMOKE_WIDTH,
                INPUT_SMOKE_HEIGHT) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
    librdp_session_set_event_callback(session,
                                      input_smoke_client_event,
                                      &state);
    REQUIRE(librdp_trace_policy_init(&trace_policy) ==
            LIBRDP_STATUS_OK);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.hex_bytes = 96u;
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = input_smoke_trace;
    trace_policy.callback_user_data = &state;
    if (mode == INPUT_SMOKE_TOUCH)
        trace_policy.trace_id = "input-touch-smoke";
    else if (mode == INPUT_SMOKE_TOUCH_FALLBACK)
        trace_policy.trace_id =
            "input-touch-fallback-smoke";
    else if (mode == INPUT_SMOKE_PEN)
        trace_policy.trace_id = "input-pen-smoke";
    else if (mode == INPUT_SMOKE_CORE)
        trace_policy.trace_id = "input-core-smoke";
    else
        trace_policy.trace_id =
            "input-core-fallback-smoke";
    REQUIRE(librdp_session_set_trace_policy(
                session,
                &trace_policy) == LIBRDP_STATUS_OK);
    REQUIRE(librdp_session_connect(session) ==
            LIBRDP_STATUS_OK);
    input_smoke_prepare_touch(frames, contacts);
    input_smoke_prepare_pen(pen_frames, pen_contacts);
    key.scancode = 0x1eu;
    key.state = LIBRDP_KEY_PRESSED;
    mouse.x = 17u;
    mouse.y = 19u;
    mouse.button = LIBRDP_MOUSE_BUTTON_NONE;
    mouse.state = LIBRDP_MOUSE_MOVED;
    for (attempt = 0u;
         attempt < INPUT_SMOKE_PUMP_LIMIT;
         attempt++)
    {
        librdp_status status =
            librdp_session_run_once(session, 20);

        REQUIRE(status == LIBRDP_STATUS_OK);
        if (mode == INPUT_SMOKE_TOUCH && !sent)
        {
            status = librdp_session_send_touch(
                session,
                INPUT_SMOKE_ENCODE_TIME,
                frames,
                3u);
            if (status == LIBRDP_STATUS_OK)
                sent = 1;
            else
                REQUIRE(status == LIBRDP_STATUS_STATE);
        }
        else if (mode == INPUT_SMOKE_PEN && !sent)
        {
            status = librdp_session_send_pen(
                session,
                INPUT_SMOKE_ENCODE_TIME,
                pen_frames,
                4u);
            if (status == LIBRDP_STATUS_OK)
                sent = 1;
            else
                REQUIRE(status == LIBRDP_STATUS_STATE);
        }
        else if (mode == INPUT_SMOKE_TOUCH_FALLBACK &&
                 !sent &&
                 state.active_events > 0u)
        {
            REQUIRE(librdp_session_send_touch(
                        session,
                        INPUT_SMOKE_ENCODE_TIME,
                        frames,
                        3u) == LIBRDP_STATUS_STATE);
            REQUIRE(librdp_session_send_mouse(
                        session,
                        &mouse) == LIBRDP_STATUS_OK);
            sent = 1;
        }
        else if (((mode == INPUT_SMOKE_CORE &&
                   state.core_ready > 0u) ||
                  (mode == INPUT_SMOKE_CORE_FALLBACK &&
                   state.active_events > 0u)) &&
                 !sent)
        {
            REQUIRE(librdp_session_send_key(
                        session,
                        &key) == LIBRDP_STATUS_OK);
            REQUIRE(librdp_session_send_mouse(
                        session,
                        &mouse) == LIBRDP_STATUS_OK);
            sent = 1;
        }
        if (sent &&
            ((mode == INPUT_SMOKE_TOUCH &&
              atomic_load_explicit(&fixture.touch_received,
                                   memory_order_acquire) == 1u) ||
             (mode == INPUT_SMOKE_PEN &&
              atomic_load_explicit(&fixture.pen_received,
                                   memory_order_acquire) == 1u) ||
             (mode == INPUT_SMOKE_TOUCH_FALLBACK &&
              atomic_load_explicit(
                  &fixture.classic_mouse_received,
                  memory_order_acquire) == 1u) ||
             (mode == INPUT_SMOKE_CORE &&
              atomic_load_explicit(&fixture.core_key_received,
                                   memory_order_acquire) == 1u &&
              atomic_load_explicit(&fixture.core_mouse_received,
                                   memory_order_acquire) == 1u) ||
             (mode == INPUT_SMOKE_CORE_FALLBACK &&
              atomic_load_explicit(
                  &fixture.classic_key_received,
                  memory_order_acquire) == 1u &&
              atomic_load_explicit(
                  &fixture.classic_mouse_received,
                  memory_order_acquire) == 1u)))
            break;
    }
    REQUIRE(attempt < INPUT_SMOKE_PUMP_LIMIT);
    REQUIRE(sent);
    REQUIRE(atomic_load_explicit(&fixture.channel_open,
                                 memory_order_acquire) ==
            ((mode == INPUT_SMOKE_TOUCH ||
              mode == INPUT_SMOKE_PEN ||
              mode == INPUT_SMOKE_CORE)
                 ? 1u
                 : 0u));
    REQUIRE(atomic_load_explicit(&fixture.client_ready,
                                 memory_order_acquire) ==
            ((mode == INPUT_SMOKE_TOUCH ||
              mode == INPUT_SMOKE_PEN)
                 ? 1u
                 : 0u));
    REQUIRE(atomic_load_explicit(&fixture.touch_received,
                                 memory_order_acquire) ==
            (mode == INPUT_SMOKE_TOUCH ? 1u : 0u));
    REQUIRE(atomic_load_explicit(&fixture.pen_received,
                                 memory_order_acquire) ==
            (mode == INPUT_SMOKE_PEN ? 1u : 0u));
    REQUIRE(atomic_load_explicit(&fixture.core_init_received,
                                 memory_order_acquire) ==
            (mode == INPUT_SMOKE_CORE ? 1u : 0u));
    REQUIRE(atomic_load_explicit(&fixture.core_key_received,
                                 memory_order_acquire) ==
            (mode == INPUT_SMOKE_CORE ? 1u : 0u));
    REQUIRE(atomic_load_explicit(&fixture.core_mouse_received,
                                 memory_order_acquire) ==
            (mode == INPUT_SMOKE_CORE ? 1u : 0u));
    REQUIRE(atomic_load_explicit(&fixture.classic_key_received,
                                 memory_order_acquire) ==
            (mode == INPUT_SMOKE_CORE_FALLBACK ? 1u : 0u));
    REQUIRE(atomic_load_explicit(&fixture.classic_mouse_received,
                                 memory_order_acquire) ==
            ((mode == INPUT_SMOKE_TOUCH_FALLBACK ||
              mode == INPUT_SMOKE_CORE_FALLBACK)
                 ? 1u
                 : 0u));
    REQUIRE(atomic_load_explicit(&fixture.validation_errors,
                                 memory_order_acquire) == 0u);
    REQUIRE(state.active_events == 1u);
    REQUIRE(state.error_events == 0u);
    REQUIRE(state.trace_errors == 0u);
    REQUIRE(state.channel_ready ==
            ((mode == INPUT_SMOKE_TOUCH ||
              mode == INPUT_SMOKE_PEN)
                 ? 1u
                 : 0u));
    REQUIRE(state.touch_sent ==
            (mode == INPUT_SMOKE_TOUCH ? 1u : 0u));
    REQUIRE(state.pen_sent ==
            (mode == INPUT_SMOKE_PEN ? 1u : 0u));
    REQUIRE(state.core_ready ==
            (mode == INPUT_SMOKE_CORE ? 1u : 0u));
    REQUIRE(state.key_sent ==
            ((mode == INPUT_SMOKE_CORE ||
              mode == INPUT_SMOKE_CORE_FALLBACK)
                 ? 1u
                 : 0u));
    REQUIRE(state.mouse_sent ==
            ((mode == INPUT_SMOKE_TOUCH_FALLBACK ||
              mode == INPUT_SMOKE_CORE ||
              mode == INPUT_SMOKE_CORE_FALLBACK)
                 ? 1u
                 : 0u));
    REQUIRE(state.core_key_sent ==
            (mode == INPUT_SMOKE_CORE ? 1u : 0u));
    REQUIRE(state.core_mouse_sent ==
            (mode == INPUT_SMOKE_CORE ? 1u : 0u));
    REQUIRE(state.slow_key_sent ==
            (mode == INPUT_SMOKE_CORE_FALLBACK ? 1u : 0u));
    REQUIRE(state.slow_mouse_sent ==
            ((mode == INPUT_SMOKE_TOUCH_FALLBACK ||
              mode == INPUT_SMOKE_CORE_FALLBACK)
                 ? 1u
                 : 0u));
    REQUIRE(librdp_session_disconnect(session) ==
            LIBRDP_STATUS_OK);
    REQUIRE(pthread_join(fixture.thread, NULL) == 0);
    thread_started = 0;
    REQUIRE(fixture.status == LIBRDP_STATUS_OK);
    REQUIRE(atomic_load_explicit(&fixture.client_closed,
                                 memory_order_acquire) == 1u);
    result = 0;

cleanup:
    if (session)
        (void)librdp_session_disconnect(session);
    atomic_store_explicit(&fixture.stop,
                          1u,
                          memory_order_release);
    if (thread_started)
        (void)pthread_join(fixture.thread, NULL);
    librdp_session_free(session);
    librdp_settings_free(settings);
    return result;
}

int main(int argc, char** argv)
{
    if (argc == 2 && strcmp(argv[1], "touch") == 0)
        return input_smoke_run(INPUT_SMOKE_TOUCH);
    if (argc == 2 && strcmp(argv[1], "touch-fallback") == 0)
        return input_smoke_run(INPUT_SMOKE_TOUCH_FALLBACK);
    if (argc == 2 && strcmp(argv[1], "pen") == 0)
        return input_smoke_run(INPUT_SMOKE_PEN);
    if (argc == 2 && strcmp(argv[1], "core") == 0)
        return input_smoke_run(INPUT_SMOKE_CORE);
    if (argc == 2 &&
        strcmp(argv[1], "core-fallback") == 0)
        return input_smoke_run(INPUT_SMOKE_CORE_FALLBACK);
    fprintf(stderr,
            "usage: test_server_client_input_smoke "
            "touch|touch-fallback|pen|core|core-fallback\n");
    return 2;
}
