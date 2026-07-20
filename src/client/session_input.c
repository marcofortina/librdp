/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: public session input APIs for keyboard, pointer, touch, and pen events.
 * Invariants: input is sent only after activation and uses Core Input only after negotiation.
 * Ownership: temporary serialized input buffers are local; callbacks receive copied public event structs.
 * Threading: entry points enforce the session owner-thread contract before writing transport data.
 * Trust boundary: caller-provided scancodes, Unicode values, contacts, and coordinates are validated before serialization.
 */

#include "client/session_internal.h"
#include "common/trace.h"
#include "input/input.h"
#include "protocol/slowpath.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static librdp_status rdp_session_require_input_channel(const librdp_session* session)
{
    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (!session->input_channel_ready || session->input_channel_suspended ||
        session->input_channel_id_bytes == 0)
        return LIBRDP_STATUS_STATE;
    return LIBRDP_STATUS_OK;
}


static void rdp_session_free_buffers(rdp_buffer* buffers, uint16_t count)
{
    uint16_t i = 0;

    if (!buffers)
        return;
    for (i = 0; i < count; i++)
        rdp_buffer_free(&buffers[i]);
    free(buffers);
}

static void rdp_session_copy_touch_contact(const librdp_touch_contact* in,
                                           rdp_input_channel_touch_contact* out)
{
    memset(out, 0, sizeof(*out));
    out->contact_id = in->contact_id;
    out->fields_present = in->fields_present;
    out->x = in->x;
    out->y = in->y;
    out->contact_flags = in->contact_flags;
    out->contact_rect_left = in->contact_rect_left;
    out->contact_rect_top = in->contact_rect_top;
    out->contact_rect_right = in->contact_rect_right;
    out->contact_rect_bottom = in->contact_rect_bottom;
    out->orientation = in->orientation;
    out->pressure = in->pressure;
}

static void rdp_session_copy_pen_contact(const librdp_pen_contact* in,
                                         rdp_input_channel_pen_contact* out)
{
    memset(out, 0, sizeof(*out));
    out->device_id = in->device_id;
    out->fields_present = in->fields_present;
    out->x = in->x;
    out->y = in->y;
    out->contact_flags = in->contact_flags;
    out->pen_flags = in->pen_flags;
    out->pressure = in->pressure;
    out->rotation = in->rotation;
    out->tilt_x = in->tilt_x;
    out->tilt_y = in->tilt_y;
}

static librdp_status rdp_session_validate_touch_frames(const librdp_touch_frame* frames,
                                                       uint16_t frame_count,
                                                       uint16_t max_touch_contacts)
{
    uint16_t i = 0;

    if (!frames || frame_count == 0 || max_touch_contacts == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < frame_count; i++)
    {
        uint8_t seen[RDP_INPUT_CHANNEL_MAX_FRAME_CONTACTS];
        uint16_t j = 0;

        if (!frames[i].contacts ||
            frames[i].contact_count == 0 ||
            frames[i].contact_count > max_touch_contacts ||
            frames[i].contact_count > RDP_INPUT_CHANNEL_MAX_FRAME_CONTACTS)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        memset(seen, 0, sizeof(seen));
        for (j = 0; j < frames[i].contact_count; j++)
        {
            rdp_input_channel_touch_contact contact;

            rdp_session_copy_touch_contact(&frames[i].contacts[j], &contact);
            if (seen[contact.contact_id] ||
                rdp_input_channel_validate_touch_contact(&contact) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_INVALID_ARGUMENT;
            seen[contact.contact_id] = 1u;
        }
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_validate_pen_frames(const librdp_pen_frame* frames, uint16_t frame_count)
{
    uint16_t i = 0;

    if (!frames || frame_count == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (i = 0; i < frame_count; i++)
    {
        uint8_t seen[RDP_INPUT_CHANNEL_MAX_FRAME_CONTACTS];
        uint16_t j = 0;

        if (!frames[i].contacts ||
            frames[i].contact_count == 0 ||
            frames[i].contact_count > RDP_INPUT_CHANNEL_MAX_FRAME_CONTACTS)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        memset(seen, 0, sizeof(seen));
        for (j = 0; j < frames[i].contact_count; j++)
        {
            rdp_input_channel_pen_contact contact;

            rdp_session_copy_pen_contact(&frames[i].contacts[j], &contact);
            if (seen[contact.device_id] ||
                rdp_input_channel_validate_pen_contact(&contact) != LIBRDP_STATUS_OK)
                return LIBRDP_STATUS_INVALID_ARGUMENT;
            seen[contact.device_id] = 1u;
        }
    }
    return LIBRDP_STATUS_OK;
}

/*
 * Serialize one keyboard input event for the connected session. Scancode,
 * Unicode fallback, and release state are validated before the event is
 * written to the selected input path.
 */
static librdp_status rdp_session_send_key_inner(librdp_session* session, const librdp_key_event* key)
{
    uint16_t flags = 0;
    rdp_buffer input;
    librdp_event event;
    librdp_status status = LIBRDP_STATUS_OK;
    const int use_unicode = key && ((key->flags & LIBRDP_KEY_FLAG_UNICODE) != 0);
    const int use_core_input = key && session && session->core_input_ready;

    if (!session || !key)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->share_id == 0)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&input);
    if (use_core_input)
    {
        if (use_unicode)
        {
            if (key->unicode > 0xffffu)
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            else
                status = rdp_core_input_write_unicode_event(&input,
                                                            (uint16_t)key->unicode,
                                                            key->state == LIBRDP_KEY_RELEASED ? 1u : 0u);
        }
        else if (key->scancode > 0xffu)
        {
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
        }
        else
        {
            uint8_t core_flags = key->state == LIBRDP_KEY_RELEASED ? RDP_CORE_INPUT_KBDFLAGS_RELEASE : 0;

            if ((key->flags & LIBRDP_KEY_FLAG_EXTENDED) != 0)
                core_flags = (uint8_t)(core_flags | RDP_CORE_INPUT_KBDFLAGS_EXTENDED);
            if ((key->flags & LIBRDP_KEY_FLAG_EXTENDED1) != 0)
                core_flags = (uint8_t)(core_flags | RDP_CORE_INPUT_KBDFLAGS_EXTENDED1);
            status = rdp_core_input_write_keyboard_event_ex(&input, (uint8_t)key->scancode, core_flags);
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_dynamic_channel_data(session,
                                                           session->core_input_channel_id,
                                                           session->core_input_channel_id_bytes,
                                                           input.data,
                                                           input.length,
                                                           "client.core_input.keyboard");
    }
    else
    {
        status = rdp_input_make_keyboard_flags(key, &flags);
        if (status == LIBRDP_STATUS_OK && use_unicode)
            status = rdp_slowpath_write_client_unicode_keyboard_input(&input,
                                                                      session->share_id,
                                                                      session->mcs_user_id,
                                                                      flags,
                                                                      (uint16_t)key->unicode);
        else if (status == LIBRDP_STATUS_OK)
            status = rdp_slowpath_write_client_keyboard_input(&input,
                                                              session->share_id,
                                                              session->mcs_user_id,
                                                              flags,
                                                              (uint16_t)key->scancode);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_write_slowpath_pdu(session, &input, "rdp.input.keyboard");
    }
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&input);
        return status;
    }

    event.type = LIBRDP_EVENT_KEY_SENT;
    event.data.key = *key;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.input.send",
                    "kind=keyboard scancode=%u unicode_present=%u transport=%s flags=%u",
                    key->scancode,
                    use_unicode ? 1u : 0u,
                    use_core_input ? "core_input" : "slowpath",
                    use_core_input ? (key->state == LIBRDP_KEY_RELEASED ? 1u : 0u) : flags);
    rdp_buffer_free(&input);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_send_key(librdp_session* session, const librdp_key_event* key)
{
    rdp_trace_session_scope trace_scope;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return rdp_session_send_key_inner(session, key);
    status = rdp_session_require_owner(session, "client.input.key.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_session_trace_scope_begin(session, &trace_scope);
    status = rdp_session_send_key_inner(session, key);
    rdp_session_trace_scope_end(session, &trace_scope);
    return status;
}

/*
 * Serialize one pointer input event for the connected session. Coordinates,
 * wheel data, and button flags are normalized before the event enters the core
 * input stream.
 */
static librdp_status rdp_session_send_mouse_inner(librdp_session* session, const librdp_mouse_event* mouse)
{
    uint16_t flags = 0;
    rdp_buffer input;
    librdp_event event;
    librdp_status status = LIBRDP_STATUS_OK;
    int use_extended = 0;
    int use_core_input = 0;

    if (!session || !mouse)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->share_id == 0)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&input);
    use_extended = rdp_input_mouse_uses_extended(mouse);
    use_core_input = session->core_input_ready;
    status = rdp_input_make_pointer_flags(mouse, &flags);
    if (status == LIBRDP_STATUS_OK)
    {
        if (use_core_input)
        {
            if (use_extended)
                status = rdp_core_input_write_extended_mouse_event(&input,
                                                                   flags,
                                                                   mouse->x,
                                                                   mouse->y);
            else
                status = rdp_core_input_write_mouse_event(&input, flags, mouse->x, mouse->y);
        }
        else if (use_extended)
            status = rdp_slowpath_write_client_extended_mouse_input(&input,
                                                                    session->share_id,
                                                                    session->mcs_user_id,
                                                                    flags,
                                                                    mouse->x,
                                                                    mouse->y);
        else
            status = rdp_slowpath_write_client_mouse_input(&input,
                                                           session->share_id,
                                                           session->mcs_user_id,
                                                           flags,
                                                           mouse->x,
                                                           mouse->y);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        if (use_core_input)
            status = rdp_session_send_dynamic_channel_data(session,
                                                           session->core_input_channel_id,
                                                           session->core_input_channel_id_bytes,
                                                           input.data,
                                                           input.length,
                                                           use_extended ? "client.core_input.mousex" :
                                                                          "client.core_input.mouse");
        else if (use_extended)
            status = rdp_session_write_slowpath_pdu(session, &input, "rdp.input.mousex");
        else
            status = rdp_session_write_slowpath_pdu(session, &input, "rdp.input.mouse");
    }
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&input);
        return status;
    }

    event.type = LIBRDP_EVENT_MOUSE_SENT;
    event.data.mouse = *mouse;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.input.send",
                    "kind=mouse x=%u y=%u transport=%s flags=%u",
                    mouse->x,
                    mouse->y,
                    use_core_input ? (use_extended ? "core_input_mousex" : "core_input") :
                                     (use_extended ? "slowpath_mousex" : "slowpath"),
                    flags);
    rdp_buffer_free(&input);
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_send_mouse(librdp_session* session, const librdp_mouse_event* mouse)
{
    rdp_trace_session_scope trace_scope;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return rdp_session_send_mouse_inner(session, mouse);
    status = rdp_session_require_owner(session, "client.input.mouse.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_session_trace_scope_begin(session, &trace_scope);
    status = rdp_session_send_mouse_inner(session, mouse);
    rdp_session_trace_scope_end(session, &trace_scope);
    return status;
}

static librdp_status rdp_session_send_touch_inner(
    librdp_session* session,
    uint32_t encode_time,
    const librdp_touch_frame* frames,
    uint16_t frame_count)
{
    rdp_input_channel_touch_frame* internal_frames = NULL;
    rdp_buffer* contact_buffers = NULL;
    rdp_buffer input;
    uint16_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !frames || frame_count == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_validate_touch_frames(frames,
                                               frame_count,
                                               RDP_INPUT_CHANNEL_MAX_FRAME_CONTACTS);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_session_require_input_channel(session);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_session_validate_touch_frames(frames,
                                               frame_count,
                                               session->input_channel_max_touch_contacts);
    if (status != LIBRDP_STATUS_OK)
        return status;

    internal_frames = (rdp_input_channel_touch_frame*)calloc(frame_count, sizeof(*internal_frames));
    contact_buffers = (rdp_buffer*)calloc(frame_count, sizeof(*contact_buffers));
    if (!internal_frames || !contact_buffers)
    {
        free(internal_frames);
        free(contact_buffers);
        return LIBRDP_STATUS_NO_MEMORY;
    }

    for (i = 0; status == LIBRDP_STATUS_OK && i < frame_count; i++)
    {
        uint16_t j = 0;

        rdp_buffer_init(&contact_buffers[i]);
        for (j = 0; status == LIBRDP_STATUS_OK && j < frames[i].contact_count; j++)
        {
            rdp_input_channel_touch_contact contact;

            rdp_session_copy_touch_contact(&frames[i].contacts[j], &contact);
            status = rdp_input_channel_write_touch_contact(&contact_buffers[i], &contact);
        }
        internal_frames[i].contact_count = frames[i].contact_count;
        internal_frames[i].frame_offset = frames[i].frame_offset;
        internal_frames[i].contacts = contact_buffers[i].data;
        internal_frames[i].contacts_len = contact_buffers[i].length;
    }

    rdp_buffer_init(&input);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_input_channel_write_touch_event(&input, encode_time, internal_frames, frame_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->input_channel_id,
                                                       session->input_channel_id_bytes,
                                                       input.data,
                                                       input.length,
                                                       "client.input_channel.touch");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.input_channel.touch_send",
                        "frames=%u encode_time=%u",
                        frame_count,
                        encode_time);
    rdp_buffer_free(&input);
    rdp_session_free_buffers(contact_buffers, frame_count);
    free(internal_frames);
    return status;
}

librdp_status librdp_session_send_touch(librdp_session* session,
                                        uint32_t encode_time,
                                        const librdp_touch_frame* frames,
                                        uint16_t frame_count)
{
    rdp_trace_session_scope trace_scope;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return rdp_session_send_touch_inner(session,
                                            encode_time,
                                            frames,
                                            frame_count);
    status = rdp_session_require_owner(
        session,
        "client.input.touch.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_session_trace_scope_begin(session, &trace_scope);
    status = rdp_session_send_touch_inner(session,
                                          encode_time,
                                          frames,
                                          frame_count);
    rdp_session_trace_scope_end(session, &trace_scope);
    return status;
}

static librdp_status rdp_session_send_pen_inner(
    librdp_session* session,
    uint32_t encode_time,
    const librdp_pen_frame* frames,
    uint16_t frame_count)
{
    rdp_input_channel_pen_frame* internal_frames = NULL;
    rdp_buffer* contact_buffers = NULL;
    rdp_buffer input;
    uint16_t i = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !frames || frame_count == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_session_validate_pen_frames(frames, frame_count);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_session_require_input_channel(session);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (!session->input_channel_supports_pen)
        return LIBRDP_STATUS_UNSUPPORTED;

    internal_frames = (rdp_input_channel_pen_frame*)calloc(frame_count, sizeof(*internal_frames));
    contact_buffers = (rdp_buffer*)calloc(frame_count, sizeof(*contact_buffers));
    if (!internal_frames || !contact_buffers)
    {
        free(internal_frames);
        free(contact_buffers);
        return LIBRDP_STATUS_NO_MEMORY;
    }

    for (i = 0; status == LIBRDP_STATUS_OK && i < frame_count; i++)
    {
        uint16_t j = 0;

        rdp_buffer_init(&contact_buffers[i]);
        for (j = 0; status == LIBRDP_STATUS_OK && j < frames[i].contact_count; j++)
        {
            rdp_input_channel_pen_contact contact;

            rdp_session_copy_pen_contact(&frames[i].contacts[j], &contact);
            status = rdp_input_channel_write_pen_contact(&contact_buffers[i], &contact);
        }
        internal_frames[i].contact_count = frames[i].contact_count;
        internal_frames[i].frame_offset = frames[i].frame_offset;
        internal_frames[i].contacts = contact_buffers[i].data;
        internal_frames[i].contacts_len = contact_buffers[i].length;
    }

    rdp_buffer_init(&input);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_input_channel_write_pen_event(&input, encode_time, internal_frames, frame_count);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->input_channel_id,
                                                       session->input_channel_id_bytes,
                                                       input.data,
                                                       input.length,
                                                       "client.input_channel.pen");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.input_channel.pen_send",
                        "frames=%u encode_time=%u",
                        frame_count,
                        encode_time);
    rdp_buffer_free(&input);
    rdp_session_free_buffers(contact_buffers, frame_count);
    free(internal_frames);
    return status;
}

librdp_status librdp_session_send_pen(librdp_session* session,
                                      uint32_t encode_time,
                                      const librdp_pen_frame* frames,
                                      uint16_t frame_count)
{
    rdp_trace_session_scope trace_scope;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return rdp_session_send_pen_inner(session,
                                          encode_time,
                                          frames,
                                          frame_count);
    status = rdp_session_require_owner(
        session,
        "client.input.pen.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_session_trace_scope_begin(session, &trace_scope);
    status = rdp_session_send_pen_inner(session,
                                        encode_time,
                                        frames,
                                        frame_count);
    rdp_session_trace_scope_end(session, &trace_scope);
    return status;
}

static librdp_status rdp_session_dismiss_touch_inner(
    librdp_session* session,
    uint8_t contact_id)
{
    rdp_buffer input;
    librdp_status status =
        rdp_session_require_input_channel(session);

    rdp_buffer_init(&input);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_input_channel_write_dismiss_hovering(&input, contact_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->input_channel_id,
                                                       session->input_channel_id_bytes,
                                                       input.data,
                                                       input.length,
                                                       "client.input_channel.dismiss_hovering");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.input_channel.dismiss_hovering_send",
                        "contact_id=%u",
                        contact_id);
    rdp_buffer_free(&input);
    return status;
}

librdp_status librdp_session_dismiss_touch(librdp_session* session,
                                           uint8_t contact_id)
{
    rdp_trace_session_scope trace_scope;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return rdp_session_dismiss_touch_inner(session,
                                               contact_id);
    status = rdp_session_require_owner(
        session,
        "client.input.dismiss_touch.owner");
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_session_trace_scope_begin(session, &trace_scope);
    status = rdp_session_dismiss_touch_inner(session,
                                             contact_id);
    rdp_session_trace_scope_end(session, &trace_scope);
    return status;
}
