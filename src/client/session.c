#include <librdp/session.h>

#include "channels/core_input.h"
#include "channels/display_control.h"
#include "channels/dynamic_channel.h"
#include "channels/graphics_pipeline.h"
#include "channels/mouse_cursor.h"
#include "channels/virtual_channel.h"
#include "client/settings_internal.h"
#include "common/stream.h"
#include "common/trace.h"
#include "graphics/bitmap.h"
#include "graphics/clearcodec.h"
#include "graphics/rfx_codec.h"
#include "licensing/licensing.h"
#include "nla/credssp.h"
#include "protocol/fastpath.h"
#include "protocol/gcc.h"
#include "protocol/mcs.h"
#include "protocol/pointer.h"
#include "protocol/slowpath.h"
#include "protocol/tpkt.h"
#include "protocol/x224.h"
#include "security/security.h"
#include "transport/transport.h"
#include "input/input.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define RDP_SESSION_MAX_DYNAMIC_CHANNELS 64u
#define RDP_SESSION_DYNAMIC_CHANNEL_NAME_MAX 96u
#define RDP_SESSION_MAX_DYNAMIC_MESSAGE (64u * 1024u * 1024u)
#define RDP_SESSION_MAX_GRAPHICS_SURFACES 64u
#define RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION 8192u
#define RDP_SESSION_GRAPHICS_CACHE_SLOTS 4096u
#define RDP_SESSION_GRAPHICS_CACHE_MAX_BYTES (16u * 1024u * 1024u)
#define RDP_SESSION_PROGRESSIVE_TILE_STATES 2048u
#define RDP_SESSION_POINTER_CACHE_SLOTS 128u
#define RDP_SESSION_DISPLAY_CONTROL_NAME "Microsoft::Windows::RDS::DisplayControl"
#define RDP_SESSION_CORE_INPUT_NAME "Microsoft::Windows::RDS::CoreInput"
#define RDP_SESSION_GRAPHICS_PIPELINE_NAME "Microsoft::Windows::RDS::Graphics"
#define RDP_SESSION_MOUSE_CURSOR_NAME "Microsoft::Windows::RDS::MouseCursor"

typedef struct rdp_session_dynamic_channel
{
    uint32_t channel_id;
    uint8_t channel_id_bytes;
    uint8_t active;
    uint8_t fragmenting;
    uint32_t fragment_expected;
    rdp_buffer fragment;
    char name[RDP_SESSION_DYNAMIC_CHANNEL_NAME_MAX];
} rdp_session_dynamic_channel;

typedef struct rdp_session_graphics_surface
{
    uint8_t active;
    uint8_t mapped;
    uint16_t surface_id;
    uint16_t width;
    uint16_t height;
    uint8_t pixel_format;
    uint32_t output_origin_x;
    uint32_t output_origin_y;
    rdp_buffer pixels;
} rdp_session_graphics_surface;

typedef struct rdp_session_graphics_cache_entry
{
    uint8_t active;
    uint16_t cache_slot;
    uint16_t width;
    uint16_t height;
    uint64_t cache_key;
    rdp_buffer pixels;
} rdp_session_graphics_cache_entry;

typedef struct rdp_session_progressive_tile_cache
{
    uint8_t active;
    uint16_t surface_id;
    uint16_t x_idx;
    uint16_t y_idx;
    uint64_t last_used;
    rdp_rfx_progressive_tile_state* state;
} rdp_session_progressive_tile_cache;

typedef struct rdp_session_pointer_cache_entry
{
    uint8_t active;
    librdp_pointer_event pointer;
    rdp_buffer pixels;
} rdp_session_pointer_cache_entry;

struct librdp_session
{
    librdp_settings* settings;
    librdp_surface* surface;
    rdp_transport transport;
    uint16_t mcs_user_id;
    uint16_t dynamic_channel_id;
    uint32_t core_input_channel_id;
    uint8_t core_input_channel_id_bytes;
    uint8_t core_input_ready;
    uint32_t display_control_channel_id;
    uint8_t display_control_channel_id_bytes;
    uint8_t display_control_ready;
    rdp_display_control_caps display_control_caps;
    uint32_t requested_desktop_width;
    uint32_t requested_desktop_height;
    uint32_t sent_desktop_width;
    uint32_t sent_desktop_height;
    uint32_t graphics_channel_id;
    uint8_t graphics_channel_id_bytes;
    uint8_t graphics_ready;
    uint32_t graphics_selected_version;
    uint32_t graphics_selected_flags;
    uint32_t graphics_frames_decoded;
    uint32_t graphics_frame_active;
    uint8_t graphics_dirty_pending;
    uint32_t graphics_dirty_left;
    uint32_t graphics_dirty_top;
    uint32_t graphics_dirty_right;
    uint32_t graphics_dirty_bottom;
    uint32_t mouse_cursor_channel_id;
    uint8_t mouse_cursor_channel_id_bytes;
    uint8_t mouse_cursor_ready;
    rdp_graphics_decompressor graphics_decompressor;
    rdp_clearcodec_context clearcodec;
    rdp_session_graphics_surface graphics_surfaces[RDP_SESSION_MAX_GRAPHICS_SURFACES];
    rdp_session_graphics_cache_entry graphics_cache[RDP_SESSION_GRAPHICS_CACHE_SLOTS];
    rdp_session_progressive_tile_cache progressive_tiles[RDP_SESSION_PROGRESSIVE_TILE_STATES];
    rdp_session_pointer_cache_entry pointer_cache[RDP_SESSION_POINTER_CACHE_SLOTS];
    uint64_t progressive_tile_clock;
    size_t graphics_cache_bytes;
    uint32_t graphics_current_frame_id;
    rdp_session_dynamic_channel dynamic_channels[RDP_SESSION_MAX_DYNAMIC_CHANNELS];
    rdp_standard_security_context standard_security;
    uint32_t share_id;
    librdp_session_state state;
    uint8_t standard_security_active;
    librdp_event_callback callback;
    void* callback_data;
};

static void rdp_session_emit(librdp_session* session, const librdp_event* event)
{
    if (session && session->callback && event)
        session->callback(session, event, session->callback_data);
}

static void rdp_session_set_state(librdp_session* session, librdp_session_state state)
{
    librdp_event event;
    librdp_session_state old_state = LIBRDP_SESSION_IDLE;

    if (!session || session->state == state)
        return;

    old_state = session->state;
    session->state = state;

    event.type = LIBRDP_EVENT_STATE_CHANGED;
    event.data.state.old_state = (int)old_state;
    event.data.state.new_state = (int)state;
    rdp_session_emit(session, &event);
}

static librdp_status rdp_session_fail(librdp_session* session, librdp_status status)
{
    librdp_event event;

    rdp_session_set_state(session, LIBRDP_SESSION_FAILED);
    event.type = LIBRDP_EVENT_ERROR;
    event.data.error.status = status;
    rdp_session_emit(session, &event);
    return status;
}

static void rdp_session_emit_surface_invalidated(librdp_session* session,
                                                 uint32_t x,
                                                 uint32_t y,
                                                 uint32_t width,
                                                 uint32_t height)
{
    librdp_event event;

    if (!session || width == 0 || height == 0)
        return;
    event.type = LIBRDP_EVENT_SURFACE_INVALIDATED;
    event.data.surface.x = x;
    event.data.surface.y = y;
    event.data.surface.width = width;
    event.data.surface.height = height;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.surface.invalidated",
                    "x=%u y=%u width=%u height=%u output_width=%u output_height=%u frame_id=%u frame_active=%u",
                    x,
                    y,
                    width,
                    height,
                    librdp_surface_width(session->surface),
                    librdp_surface_height(session->surface),
                    session->graphics_current_frame_id,
                    session->graphics_frame_active ? 1u : 0u);
}

static void rdp_session_graphics_dirty_reset(librdp_session* session)
{
    if (!session)
        return;
    session->graphics_frame_active = 0;
    session->graphics_dirty_pending = 0;
    session->graphics_dirty_left = 0;
    session->graphics_dirty_top = 0;
    session->graphics_dirty_right = 0;
    session->graphics_dirty_bottom = 0;
    session->graphics_current_frame_id = 0;
}

static void rdp_session_graphics_dirty_add(librdp_session* session,
                                           uint32_t x,
                                           uint32_t y,
                                           uint32_t width,
                                           uint32_t height)
{
    uint32_t right = 0;
    uint32_t bottom = 0;

    if (!session || width == 0 || height == 0)
        return;
    if (!session->graphics_frame_active)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.dirty.immediate",
                        "x=%u y=%u width=%u height=%u frame_id=%u",
                        x,
                        y,
                        width,
                        height,
                        session->graphics_current_frame_id);
        rdp_session_emit_surface_invalidated(session, x, y, width, height);
        return;
    }

    right = x + width;
    bottom = y + height;
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.graphics.frame.dirty.add",
                    "frame_id=%u x=%u y=%u width=%u height=%u pending=%u previous_left=%u previous_top=%u previous_right=%u previous_bottom=%u",
                    session->graphics_current_frame_id,
                    x,
                    y,
                    width,
                    height,
                    session->graphics_dirty_pending ? 1u : 0u,
                    session->graphics_dirty_left,
                    session->graphics_dirty_top,
                    session->graphics_dirty_right,
                    session->graphics_dirty_bottom);
    if (!session->graphics_dirty_pending)
    {
        session->graphics_dirty_pending = 1;
        session->graphics_dirty_left = x;
        session->graphics_dirty_top = y;
        session->graphics_dirty_right = right;
        session->graphics_dirty_bottom = bottom;
        return;
    }
    if (x < session->graphics_dirty_left)
        session->graphics_dirty_left = x;
    if (y < session->graphics_dirty_top)
        session->graphics_dirty_top = y;
    if (right > session->graphics_dirty_right)
        session->graphics_dirty_right = right;
    if (bottom > session->graphics_dirty_bottom)
        session->graphics_dirty_bottom = bottom;
}

static void rdp_session_graphics_dirty_flush(librdp_session* session)
{
    if (!session || !session->graphics_dirty_pending)
        return;
    rdp_session_emit_surface_invalidated(session,
                                         session->graphics_dirty_left,
                                         session->graphics_dirty_top,
                                         session->graphics_dirty_right - session->graphics_dirty_left,
                                         session->graphics_dirty_bottom - session->graphics_dirty_top);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.graphics.frame.flush",
                    "frame_id=%u x=%u y=%u width=%u height=%u",
                    session->graphics_current_frame_id,
                    session->graphics_dirty_left,
                    session->graphics_dirty_top,
                    session->graphics_dirty_right - session->graphics_dirty_left,
                    session->graphics_dirty_bottom - session->graphics_dirty_top);
    session->graphics_dirty_pending = 0;
}

static void rdp_session_pointer_cache_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_POINTER_CACHE_SLOTS; i++)
        rdp_buffer_free(&session->pointer_cache[i].pixels);
    memset(session->pointer_cache, 0, sizeof(session->pointer_cache));
}

static void rdp_session_pointer_emit_default(librdp_session* session)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_POINTER;
    event.data.pointer.update_type = LIBRDP_POINTER_UPDATE_DEFAULT;
    event.data.pointer.visible = 1;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.pointer.default", "visible=1");
}

static void rdp_session_pointer_emit_hidden(librdp_session* session)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_POINTER;
    event.data.pointer.update_type = LIBRDP_POINTER_UPDATE_HIDDEN;
    event.data.pointer.visible = 0;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.pointer.hidden", "visible=0");
}

static void rdp_session_pointer_emit_position(librdp_session* session, uint16_t x, uint16_t y)
{
    librdp_event event;

    if (!session)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_POINTER;
    event.data.pointer.update_type = LIBRDP_POINTER_UPDATE_POSITION;
    event.data.pointer.x = x;
    event.data.pointer.y = y;
    event.data.pointer.visible = 1;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.pointer.position", "x=%u y=%u", x, y);
}

static void rdp_session_pointer_emit_shape(librdp_session* session, const rdp_session_pointer_cache_entry* entry)
{
    librdp_event event;

    if (!session || !entry || !entry->active)
        return;
    memset(&event, 0, sizeof(event));
    event.type = LIBRDP_EVENT_POINTER;
    event.data.pointer = entry->pointer;
    event.data.pointer.pixels = entry->pixels.data;
    event.data.pointer.pixels_len = entry->pixels.length;
    event.data.pointer.visible = 1;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.pointer.shape",
                    "cache_index=%u width=%u height=%u hot_x=%u hot_y=%u pixels=%u",
                    event.data.pointer.cache_index,
                    event.data.pointer.width,
                    event.data.pointer.height,
                    event.data.pointer.hot_x,
                    event.data.pointer.hot_y,
                    (unsigned)event.data.pointer.pixels_len);
}

static librdp_status rdp_session_pointer_store_shape(librdp_session* session, const rdp_pointer_update* update)
{
    rdp_session_pointer_cache_entry* entry = NULL;
    rdp_buffer decoded;
    size_t stride = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !update || update->kind != RDP_POINTER_UPDATE_KIND_SHAPE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (update->cache_index >= RDP_SESSION_POINTER_CACHE_SLOTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_buffer_init(&decoded);
    status = rdp_pointer_decode_bgra32(update, &decoded, &stride);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&decoded);
        return status;
    }

    entry = &session->pointer_cache[update->cache_index];
    rdp_buffer_free(&entry->pixels);
    entry->pixels = decoded;
    memset(&entry->pointer, 0, sizeof(entry->pointer));
    entry->pointer.update_type = LIBRDP_POINTER_UPDATE_SHAPE;
    entry->pointer.cache_index = update->cache_index;
    entry->pointer.hot_x = update->hot_x;
    entry->pointer.hot_y = update->hot_y;
    entry->pointer.width = update->width;
    entry->pointer.height = update->height;
    entry->pointer.stride = (uint32_t)stride;
    entry->pointer.pixels = entry->pixels.data;
    entry->pointer.pixels_len = entry->pixels.length;
    entry->pointer.visible = 1;
    entry->active = 1;
    rdp_session_pointer_emit_shape(session, entry);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_pointer_apply_update(librdp_session* session, const rdp_pointer_update* update)
{
    if (!session || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    switch (update->kind)
    {
        case RDP_POINTER_UPDATE_KIND_NULL:
            rdp_session_pointer_emit_hidden(session);
            return LIBRDP_STATUS_OK;
        case RDP_POINTER_UPDATE_KIND_DEFAULT:
            rdp_session_pointer_emit_default(session);
            return LIBRDP_STATUS_OK;
        case RDP_POINTER_UPDATE_KIND_POSITION:
            rdp_session_pointer_emit_position(session, update->x, update->y);
            return LIBRDP_STATUS_OK;
        case RDP_POINTER_UPDATE_KIND_CACHED:
            if (update->cache_index >= RDP_SESSION_POINTER_CACHE_SLOTS ||
                !session->pointer_cache[update->cache_index].active)
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.pointer.cached.missing",
                                "cache_index=%u",
                                update->cache_index);
                return LIBRDP_STATUS_OK;
            }
            rdp_session_pointer_emit_shape(session, &session->pointer_cache[update->cache_index]);
            return LIBRDP_STATUS_OK;
        case RDP_POINTER_UPDATE_KIND_SHAPE:
            return rdp_session_pointer_store_shape(session, update);
        default:
            return LIBRDP_STATUS_UNSUPPORTED;
    }
}

static librdp_status rdp_session_write_mcs_pdu(librdp_session* session,
                                               const rdp_buffer* pdu,
                                               const char* event,
                                               int allow_hexdump)
{
    rdp_buffer x224_data;
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !pdu || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&x224_data);
    rdp_buffer_init(&packet);

    status = rdp_x224_wrap_data(&x224_data, pdu->data, pdu->length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_tpkt_write(&packet, x224_data.data, x224_data.length);
    if (status == LIBRDP_STATUS_OK)
    {
        if (allow_hexdump)
            rdp_trace_hexdump(event, packet.data, packet.length);
        status = rdp_transport_write_all(&session->transport, packet.data, packet.length);
    }

    rdp_buffer_free(&packet);
    rdp_buffer_free(&x224_data);
    return status;
}

static librdp_status rdp_session_write_slowpath_pdu(librdp_session* session,
                                                    const rdp_buffer* slowpath,
                                                    const char* event)
{
    rdp_buffer security_payload;
    rdp_buffer send_data;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !slowpath || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&send_data);
    if (session->standard_security_active)
        status = rdp_security_write_encrypted_pdu(&security_payload,
                                                  &session->standard_security,
                                                  0,
                                                  slowpath->data,
                                                  slowpath->length);
    else
        status = rdp_buffer_append(&security_payload, slowpath->data, slowpath->length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_send_data_request(&send_data,
                                                      session->mcs_user_id,
                                                      (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                      security_payload.data,
                                                      security_payload.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_mcs_pdu(session, &send_data, event, 1);
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security_payload);
    return status;
}

static librdp_status rdp_session_write_channel_pdu(librdp_session* session,
                                                   uint16_t channel_id,
                                                   const rdp_buffer* payload,
                                                   const char* event)
{
    rdp_buffer channel_packet;
    rdp_buffer security_payload;
    rdp_buffer send_data;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !payload || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&channel_packet);
    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&send_data);
    status = rdp_virtual_channel_write_packet(&channel_packet, payload->data, payload->length, 3);
    if (status == LIBRDP_STATUS_OK)
    {
        if (session->standard_security_active)
            status = rdp_security_write_encrypted_pdu(&security_payload,
                                                      &session->standard_security,
                                                      0,
                                                      channel_packet.data,
                                                      channel_packet.length);
        else
            status = rdp_buffer_append(&security_payload, channel_packet.data, channel_packet.length);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_send_data_request(&send_data,
                                                      session->mcs_user_id,
                                                      channel_id,
                                                      security_payload.data,
                                                      security_payload.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_mcs_pdu(session, &send_data, event, 1);
    rdp_buffer_free(&send_data);
    rdp_buffer_free(&security_payload);
    rdp_buffer_free(&channel_packet);
    return status;
}

static size_t rdp_session_dynamic_channel_header_size(uint8_t channel_id_bytes)
{
    return 1u + channel_id_bytes;
}

static uint8_t rdp_session_dynamic_length_bytes(size_t length)
{
    if (length <= 0xffu)
        return 1;
    if (length <= 0xffffu)
        return 2;
    return 4;
}

static uint32_t rdp_session_pixels_to_mm(uint16_t pixels)
{
    uint32_t mm = ((uint32_t)pixels * 254u + 480u) / 960u;

    if (mm < 10u)
        return 10u;
    if (mm > 10000u)
        return 10000u;
    return mm;
}

static librdp_status rdp_session_send_dynamic_channel_data(librdp_session* session,
                                                           uint32_t channel_id,
                                                           uint8_t channel_id_bytes,
                                                           const void* data,
                                                           size_t data_len,
                                                           const char* event)
{
    rdp_buffer response;
    size_t offset = 0;
    size_t header_size = 0;
    size_t chunk_max = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0) || !event || session->dynamic_channel_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (data_len > UINT32_MAX)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&response);
    header_size = rdp_session_dynamic_channel_header_size(channel_id_bytes);
    if (header_size >= RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE)
        status = LIBRDP_STATUS_INVALID_ARGUMENT;
    else if (status == LIBRDP_STATUS_OK && data_len <= RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE - header_size)
    {
        status = rdp_dynamic_channel_write_data(&response, channel_id, channel_id_bytes, data, data_len);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_write_channel_pdu(session, session->dynamic_channel_id, &response, event);
    }
    else if (status == LIBRDP_STATUS_OK)
    {
        uint8_t length_bytes = rdp_session_dynamic_length_bytes(data_len);

        chunk_max = RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE - header_size - length_bytes;
        if (chunk_max == 0)
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
        if (status == LIBRDP_STATUS_OK)
        {
            size_t chunk = data_len < chunk_max ? data_len : chunk_max;

            status = rdp_dynamic_channel_write_data_first(&response,
                                                          channel_id,
                                                          channel_id_bytes,
                                                          (uint32_t)data_len,
                                                          data,
                                                          chunk);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_write_channel_pdu(session, session->dynamic_channel_id, &response, event);
            offset = chunk;
        }
        while (status == LIBRDP_STATUS_OK && offset < data_len)
        {
            size_t remaining = data_len - offset;
            size_t chunk = remaining < RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE - header_size ?
                               remaining :
                               RDP_DYNAMIC_CHANNEL_MAX_PDU_SIZE - header_size;

            response.length = 0;
            status = rdp_dynamic_channel_write_data(&response,
                                                    channel_id,
                                                    channel_id_bytes,
                                                    ((const uint8_t*)data) + offset,
                                                    chunk);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_write_channel_pdu(session, session->dynamic_channel_id, &response, event);
            offset += chunk;
        }
    }
    rdp_buffer_free(&response);
    return status;
}

static rdp_session_dynamic_channel* rdp_session_dynamic_channel_find(librdp_session* session, uint32_t channel_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_MAX_DYNAMIC_CHANNELS; i++)
    {
        if (session->dynamic_channels[i].active && session->dynamic_channels[i].channel_id == channel_id)
            return &session->dynamic_channels[i];
    }
    return NULL;
}

static librdp_status rdp_session_dynamic_channel_add(librdp_session* session,
                                                     const rdp_dynamic_channel_create_request* request)
{
    size_t i = 0;
    size_t name_len = 0;
    rdp_session_dynamic_channel* entry = NULL;

    if (!session || !request || !request->name)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    entry = rdp_session_dynamic_channel_find(session, request->channel_id);
    if (!entry)
    {
        for (i = 0; i < RDP_SESSION_MAX_DYNAMIC_CHANNELS; i++)
        {
            if (!session->dynamic_channels[i].active)
            {
                entry = &session->dynamic_channels[i];
                break;
            }
        }
    }
    if (!entry)
        return LIBRDP_STATUS_UNSUPPORTED;

    rdp_buffer_free(&entry->fragment);
    memset(entry, 0, sizeof(*entry));
    entry->channel_id = request->channel_id;
    entry->channel_id_bytes = request->channel_id_bytes;
    entry->active = 1;
    name_len = request->name_len < RDP_SESSION_DYNAMIC_CHANNEL_NAME_MAX - 1u ?
                   request->name_len :
                   RDP_SESSION_DYNAMIC_CHANNEL_NAME_MAX - 1u;
    memcpy(entry->name, request->name, name_len);
    entry->name[name_len] = '\0';
    return LIBRDP_STATUS_OK;
}

static void rdp_session_dynamic_channels_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_MAX_DYNAMIC_CHANNELS; i++)
        rdp_buffer_free(&session->dynamic_channels[i].fragment);
    memset(session->dynamic_channels, 0, sizeof(session->dynamic_channels));
}

static rdp_session_graphics_surface* rdp_session_graphics_surface_find(librdp_session* session, uint16_t surface_id)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_MAX_GRAPHICS_SURFACES; i++)
    {
        if (session->graphics_surfaces[i].active && session->graphics_surfaces[i].surface_id == surface_id)
            return &session->graphics_surfaces[i];
    }
    return NULL;
}

static rdp_session_graphics_surface* rdp_session_graphics_surface_find_slot(librdp_session* session,
                                                                            uint16_t surface_id)
{
    size_t i = 0;
    rdp_session_graphics_surface* free_slot = NULL;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_MAX_GRAPHICS_SURFACES; i++)
    {
        if (session->graphics_surfaces[i].active && session->graphics_surfaces[i].surface_id == surface_id)
            return &session->graphics_surfaces[i];
        if (!session->graphics_surfaces[i].active && !free_slot)
            free_slot = &session->graphics_surfaces[i];
    }
    return free_slot;
}

static void rdp_session_progressive_tiles_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_PROGRESSIVE_TILE_STATES; i++)
    {
        free(session->progressive_tiles[i].state);
        session->progressive_tiles[i].state = NULL;
    }
    memset(session->progressive_tiles, 0, sizeof(session->progressive_tiles));
    session->progressive_tile_clock = 0;
}

static void rdp_session_progressive_tiles_clear_surface(librdp_session* session, uint16_t surface_id)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_PROGRESSIVE_TILE_STATES; i++)
    {
        rdp_session_progressive_tile_cache* entry = &session->progressive_tiles[i];

        if (entry->active && entry->surface_id == surface_id)
        {
            free(entry->state);
            memset(entry, 0, sizeof(*entry));
        }
    }
}

static rdp_session_progressive_tile_cache* rdp_session_progressive_tile_find(librdp_session* session,
                                                                             uint16_t surface_id,
                                                                             uint16_t x_idx,
                                                                             uint16_t y_idx)
{
    size_t i = 0;

    if (!session)
        return NULL;
    for (i = 0; i < RDP_SESSION_PROGRESSIVE_TILE_STATES; i++)
    {
        rdp_session_progressive_tile_cache* entry = &session->progressive_tiles[i];

        if (entry->active && entry->surface_id == surface_id &&
            entry->x_idx == x_idx && entry->y_idx == y_idx)
            return entry;
    }
    return NULL;
}

static rdp_session_progressive_tile_cache* rdp_session_progressive_tile_get(librdp_session* session,
                                                                            uint16_t surface_id,
                                                                            uint16_t x_idx,
                                                                            uint16_t y_idx,
                                                                            int create)
{
    size_t i = 0;
    rdp_session_progressive_tile_cache* entry = NULL;
    rdp_session_progressive_tile_cache* victim = NULL;

    if (!session)
        return NULL;
    entry = rdp_session_progressive_tile_find(session, surface_id, x_idx, y_idx);
    if (entry)
    {
        entry->last_used = ++session->progressive_tile_clock;
        return entry;
    }
    if (!create)
        return NULL;

    for (i = 0; i < RDP_SESSION_PROGRESSIVE_TILE_STATES; i++)
    {
        rdp_session_progressive_tile_cache* candidate = &session->progressive_tiles[i];

        if (!candidate->active)
        {
            victim = candidate;
            break;
        }
        if (!victim || candidate->last_used < victim->last_used)
            victim = candidate;
    }
    if (!victim)
        return NULL;
    if (!victim->state)
    {
        victim->state = (rdp_rfx_progressive_tile_state*)calloc(1, sizeof(*victim->state));
        if (!victim->state)
            return NULL;
    }
    else
    {
        memset(victim->state, 0, sizeof(*victim->state));
    }
    victim->active = 1;
    victim->surface_id = surface_id;
    victim->x_idx = x_idx;
    victim->y_idx = y_idx;
    victim->last_used = ++session->progressive_tile_clock;
    victim->state->x_idx = x_idx;
    victim->state->y_idx = y_idx;
    return victim;
}

static void rdp_session_graphics_surfaces_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    rdp_session_progressive_tiles_clear(session);
    for (i = 0; i < RDP_SESSION_MAX_GRAPHICS_SURFACES; i++)
        rdp_buffer_free(&session->graphics_surfaces[i].pixels);
    memset(session->graphics_surfaces, 0, sizeof(session->graphics_surfaces));
}

static librdp_status rdp_session_graphics_surface_create(librdp_session* session,
                                                         const rdp_graphics_create_surface* create)
{
    rdp_session_graphics_surface* surface = NULL;
    size_t stride = 0;
    size_t size = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !create)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (create->width == 0 || create->height == 0 ||
        create->width > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION ||
        create->height > RDP_SESSION_GRAPHICS_SURFACE_MAX_DIMENSION)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    stride = (size_t)create->width * 4u;
    if ((size_t)create->height > ((size_t)-1) / stride)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    size = stride * (size_t)create->height;

    surface = rdp_session_graphics_surface_find_slot(session, create->surface_id);
    if (!surface)
        return LIBRDP_STATUS_NO_MEMORY;

    if (surface->active)
        rdp_session_progressive_tiles_clear_surface(session, create->surface_id);
    rdp_buffer_free(&surface->pixels);
    memset(surface, 0, sizeof(*surface));
    status = rdp_buffer_reserve(&surface->pixels, size);
    if (status != LIBRDP_STATUS_OK)
        return status;
    memset(surface->pixels.data, 0, size);
    surface->pixels.length = size;
    surface->active = 1;
    surface->surface_id = create->surface_id;
    surface->width = create->width;
    surface->height = create->height;
    surface->pixel_format = create->pixel_format;
    return LIBRDP_STATUS_OK;
}

static void rdp_session_graphics_surface_delete(librdp_session* session, uint16_t surface_id)
{
    rdp_session_graphics_surface* surface = rdp_session_graphics_surface_find(session, surface_id);

    if (!surface)
        return;
    rdp_session_progressive_tiles_clear_surface(session, surface_id);
    rdp_buffer_free(&surface->pixels);
    memset(surface, 0, sizeof(*surface));
}

static uint64_t rdp_session_trace_hash_bgra(const uint8_t* pixels,
                                            uint32_t width,
                                            uint32_t height,
                                            size_t stride);
static uint64_t rdp_session_trace_surface_hash(const rdp_session_graphics_surface* surface,
                                               uint32_t x,
                                               uint32_t y,
                                               uint32_t width,
                                               uint32_t height);

static librdp_status rdp_session_graphics_surface_flush(librdp_session* session,
                                                        rdp_session_graphics_surface* surface,
                                                        uint16_t left,
                                                        uint16_t top,
                                                        uint16_t right,
                                                        uint16_t bottom,
                                                        const char* source)
{
    uint64_t dst_x64 = 0;
    uint64_t dst_y64 = 0;
    uint32_t dst_x = 0;
    uint32_t dst_y = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t output_width = 0;
    uint32_t output_height = 0;
    size_t stride = 0;
    size_t output_stride = 0;
    const uint8_t* pixels = NULL;
    const uint8_t* output_pixels = NULL;
    uint64_t source_hash = 0;
    uint64_t output_hash = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !surface->active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!surface->mapped || left >= right || top >= bottom)
        return LIBRDP_STATUS_OK;
    if (right > surface->width || bottom > surface->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    output_width = librdp_surface_width(session->surface);
    output_height = librdp_surface_height(session->surface);
    dst_x64 = (uint64_t)surface->output_origin_x + left;
    dst_y64 = (uint64_t)surface->output_origin_y + top;
    if (dst_x64 >= output_width || dst_y64 >= output_height)
        return LIBRDP_STATUS_OK;
    dst_x = (uint32_t)dst_x64;
    dst_y = (uint32_t)dst_y64;
    width = (uint32_t)(right - left);
    height = (uint32_t)(bottom - top);
    if (width > output_width - dst_x)
        width = output_width - dst_x;
    if (height > output_height - dst_y)
        height = output_height - dst_y;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_OK;

    stride = (size_t)surface->width * 4u;
    pixels = surface->pixels.data + ((size_t)top * stride) + ((size_t)left * 4u);
    source_hash = rdp_session_trace_hash_bgra(pixels, width, height, stride);
    status = librdp_surface_blit_bgra32(session->surface, dst_x, dst_y, width, height, pixels, stride);
    if (status == LIBRDP_STATUS_OK)
    {
        output_stride = librdp_surface_stride(session->surface);
        output_pixels = librdp_surface_pixels(session->surface);
        if (output_pixels)
        {
            output_hash = rdp_session_trace_hash_bgra(output_pixels + ((size_t)dst_y * output_stride) +
                                                          ((size_t)dst_x * 4u),
                                                      width,
                                                      height,
                                                      output_stride);
        }
        rdp_session_graphics_dirty_add(session, dst_x, dst_y, width, height);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.surface.flush",
                        "source=%s surface_id=%u src_x=%u src_y=%u dst_x=%u dst_y=%u width=%u height=%u surface_width=%u surface_height=%u output_width=%u output_height=%u frame_id=%u frame_active=%u source_hash=%016llx output_hash=%016llx",
                        source ? source : "unknown",
                        surface->surface_id,
                        left,
                        top,
                        dst_x,
                        dst_y,
                        width,
                        height,
                        surface->width,
                        surface->height,
                        output_width,
                        output_height,
                        session->graphics_current_frame_id,
                        session->graphics_frame_active ? 1u : 0u,
                        (unsigned long long)source_hash,
                        (unsigned long long)output_hash);
    }
    return status;
}

static librdp_status rdp_session_graphics_surface_map(librdp_session* session,
                                                      const rdp_graphics_map_surface_to_output* map)
{
    rdp_session_graphics_surface* surface = NULL;

    if (!session || !map)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    surface = rdp_session_graphics_surface_find(session, map->surface_id);
    if (!surface)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    surface->mapped = 1;
    surface->output_origin_x = map->output_origin_x;
    surface->output_origin_y = map->output_origin_y;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_surface_fill(librdp_session* session,
                                                       rdp_session_graphics_surface* surface,
                                                       const rdp_graphics_rect16* rect,
                                                       uint32_t fill_pixel)
{
    uint8_t b = (uint8_t)(fill_pixel & 0xffu);
    uint8_t g = (uint8_t)((fill_pixel >> 8) & 0xffu);
    uint8_t r = (uint8_t)((fill_pixel >> 16) & 0xffu);
    uint8_t a = 0xffu;
    size_t stride = 0;
    uint16_t y = 0;

    if (!session || !surface || !rect || !surface->active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rect->right > surface->width || rect->bottom > surface->height)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (rect->left >= rect->right || rect->top >= rect->bottom)
        return LIBRDP_STATUS_OK;
    if (surface->pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_ARGB_8888)
        a = (uint8_t)((fill_pixel >> 24) & 0xffu);

    stride = (size_t)surface->width * 4u;
    for (y = rect->top; y < rect->bottom; y++)
    {
        uint8_t* pixel = surface->pixels.data + ((size_t)y * stride) + ((size_t)rect->left * 4u);
        uint16_t x = 0;

        for (x = rect->left; x < rect->right; x++)
        {
            pixel[0] = b;
            pixel[1] = g;
            pixel[2] = r;
            pixel[3] = a;
            pixel += 4;
        }
    }
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.graphics.surface.fill.rect",
                    "source=solid_fill surface_id=%u x=%u y=%u width=%u height=%u surface_width=%u surface_height=%u fill_pixel=%08x frame_id=%u dest_hash=%016llx",
                    surface->surface_id,
                    rect->left,
                    rect->top,
                    (unsigned)(rect->right - rect->left),
                    (unsigned)(rect->bottom - rect->top),
                    surface->width,
                    surface->height,
                    fill_pixel,
                    session->graphics_current_frame_id,
                    (unsigned long long)rdp_session_trace_surface_hash(surface,
                                                                        rect->left,
                                                                        rect->top,
                                                                        (uint32_t)(rect->right - rect->left),
                                                                        (uint32_t)(rect->bottom - rect->top)));
    return rdp_session_graphics_surface_flush(session,
                                              surface,
                                              rect->left,
                                              rect->top,
                                              rect->right,
                                              rect->bottom,
                                              "solid_fill");
}

static librdp_status rdp_session_graphics_surface_write_bgra(librdp_session* session,
                                                             rdp_session_graphics_surface* surface,
                                                             uint16_t x,
                                                             uint16_t y,
                                                             uint16_t width,
                                                             uint16_t height,
                                                             const uint8_t* pixels,
                                                             size_t stride,
                                                             int force_opaque,
                                                             const char* source)
{
    uint16_t row = 0;
    size_t dest_stride = 0;
    uint64_t source_hash = 0;
    uint64_t dest_hash = 0;

    if (!session || !surface || !surface->active || !pixels)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (width == 0 || height == 0)
        return LIBRDP_STATUS_OK;
    if (x > surface->width || y > surface->height ||
        width > surface->width - x || height > surface->height - y ||
        stride < (size_t)width * 4u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    source_hash = rdp_session_trace_hash_bgra(pixels, width, height, stride);
    dest_stride = (size_t)surface->width * 4u;
    for (row = 0; row < height; row++)
    {
        uint8_t* dest = surface->pixels.data + ((size_t)(y + row) * dest_stride) + ((size_t)x * 4u);
        const uint8_t* source = pixels + ((size_t)row * stride);

        memcpy(dest, source, (size_t)width * 4u);
        if (force_opaque)
        {
            uint16_t column = 0;

            for (column = 0; column < width; column++)
                dest[((size_t)column * 4u) + 3u] = 0xffu;
        }
    }
    dest_hash = rdp_session_trace_surface_hash(surface, x, y, width, height);
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.graphics.surface.write",
                    "source=%s surface_id=%u x=%u y=%u width=%u height=%u surface_width=%u surface_height=%u stride=%u dest_stride=%u force_opaque=%u frame_id=%u source_hash=%016llx dest_hash=%016llx",
                    source ? source : "unknown",
                    surface->surface_id,
                    x,
                    y,
                    width,
                    height,
                    surface->width,
                    surface->height,
                    (unsigned)stride,
                    (unsigned)dest_stride,
                    force_opaque ? 1u : 0u,
                    session->graphics_current_frame_id,
                    (unsigned long long)source_hash,
                    (unsigned long long)dest_hash);
    return rdp_session_graphics_surface_flush(session,
                                              surface,
                                              x,
                                              y,
                                              (uint16_t)(x + width),
                                              (uint16_t)(y + height),
                                              source);
}

static librdp_status rdp_session_graphics_surface_write_wire(librdp_session* session,
                                                             rdp_session_graphics_surface* surface,
                                                             const rdp_graphics_wire_to_surface_1* wire)
{
    uint16_t width = 0;
    uint16_t height = 0;
    size_t expected = 0;

    if (!session || !surface || !wire)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (wire->dest_rect.right < wire->dest_rect.left || wire->dest_rect.bottom < wire->dest_rect.top)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    width = (uint16_t)(wire->dest_rect.right - wire->dest_rect.left);
    height = (uint16_t)(wire->dest_rect.bottom - wire->dest_rect.top);
    expected = (size_t)width * (size_t)height * 4u;
    if (wire->bitmap_data_length != expected)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_session_graphics_surface_write_bgra(session,
                                                   surface,
                                                   wire->dest_rect.left,
                                                   wire->dest_rect.top,
                                                   width,
                                                   height,
                                                   wire->bitmap_data,
                                                   (size_t)width * 4u,
                                                   wire->pixel_format == RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
                                                   "uncompressed");
}

static uint32_t rdp_session_min_u32(uint32_t a, uint32_t b)
{
    return a < b ? a : b;
}

static uint32_t rdp_session_max_u32(uint32_t a, uint32_t b)
{
    return a > b ? a : b;
}

static uint64_t rdp_session_trace_hash_seed(uint64_t hash, uint64_t value)
{
    unsigned int i = 0;

    for (i = 0; i < 8; i++)
    {
        hash ^= (uint8_t)((value >> (i * 8u)) & 0xffu);
        hash *= 1099511628211ull;
    }
    return hash;
}

static uint64_t rdp_session_trace_hash_bytes(uint64_t hash, const uint8_t* bytes, size_t length)
{
    size_t i = 0;

    for (i = 0; i < length; i++)
    {
        hash ^= bytes[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

static uint64_t rdp_session_trace_hash_bgra(const uint8_t* pixels,
                                            uint32_t width,
                                            uint32_t height,
                                            size_t stride)
{
    const size_t row_bytes = (size_t)width * 4u;
    const uint64_t offset = 1469598103934665603ull;
    uint64_t hash = offset;
    uint64_t pixel_count = 0;
    uint64_t samples = 0;
    uint64_t i = 0;

    if (!rdp_trace_enabled(RDP_TRACE_CLIENT) || !pixels || width == 0 || height == 0 || stride < row_bytes)
        return 0;

    hash = rdp_session_trace_hash_seed(hash, width);
    hash = rdp_session_trace_hash_seed(hash, height);
    pixel_count = (uint64_t)width * (uint64_t)height;
    samples = pixel_count < 8192u ? pixel_count : 8192u;
    if (samples == 0)
        return hash;
    if (samples == 1)
        return rdp_session_trace_hash_bytes(hash, pixels, 4u);

    for (i = 0; i < samples; i++)
    {
        const uint64_t pixel_index = (i * (pixel_count - 1u)) / (samples - 1u);
        const uint32_t row = (uint32_t)(pixel_index / width);
        const uint32_t column = (uint32_t)(pixel_index % width);
        const uint8_t* p = pixels + ((size_t)row * stride) + ((size_t)column * 4u);

        hash = rdp_session_trace_hash_bytes(hash, p, 4u);
    }
    return hash;
}

static uint64_t rdp_session_trace_surface_hash(const rdp_session_graphics_surface* surface,
                                               uint32_t x,
                                               uint32_t y,
                                               uint32_t width,
                                               uint32_t height)
{
    size_t stride = 0;
    const uint8_t* pixels = NULL;

    if (!surface || !surface->active || !surface->pixels.data)
        return 0;
    if (width == 0 || height == 0 || x > surface->width || y > surface->height ||
        width > (uint32_t)surface->width - x || height > (uint32_t)surface->height - y)
        return 0;
    stride = (size_t)surface->width * 4u;
    pixels = surface->pixels.data + ((size_t)y * stride) + ((size_t)x * 4u);
    return rdp_session_trace_hash_bgra(pixels, width, height, stride);
}

static librdp_status rdp_session_graphics_progressive_base_quant(const rdp_graphics_progressive_region* region,
                                                                 uint8_t quant_idx,
                                                                 rdp_rfx_component_quant* quant)
{
    if (!region || !quant)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (quant_idx >= region->quant_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return rdp_rfx_parse_component_quant(region->quant_values + ((size_t)quant_idx * 5u), 5u, quant);
}

static librdp_status rdp_session_graphics_progressive_delta_quant(const rdp_graphics_progressive_region* region,
                                                                  uint8_t progressive_idx,
                                                                  uint8_t component_idx,
                                                                  rdp_rfx_component_quant* delta)
{
    rdp_rfx_progressive_quant progressive;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!region || !delta)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(delta, 0, sizeof(*delta));
    if (progressive_idx == 0xffu)
        return LIBRDP_STATUS_OK;
    if (progressive_idx >= region->progressive_quant_count)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_rfx_parse_progressive_quant(region->progressive_quant_values + ((size_t)progressive_idx * 16u),
                                             16u,
                                             &progressive);
    if (status != LIBRDP_STATUS_OK)
        return status;

    if (component_idx == 0)
        *delta = progressive.y;
    else if (component_idx == 1)
        *delta = progressive.cb;
    else if (component_idx == 2)
        *delta = progressive.cr;
    else
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_progressive_write_region_tile(
    librdp_session* session,
    rdp_session_graphics_surface* surface,
    const rdp_graphics_progressive_region* region,
    uint32_t x,
    uint32_t y,
    uint32_t width,
    uint32_t height,
    const rdp_rfx_tile_pixels* pixels,
    int* wrote)
{
    uint16_t i = 0;
    uint32_t tile_right = 0;
    uint32_t tile_bottom = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !region || !pixels || !wrote)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (pixels->stride < RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE * 4u)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.write_region.failed",
                        "stage=stride surface_id=%u tile_x=%u tile_y=%u tile_width=%u tile_height=%u stride=%u",
                        surface ? surface->surface_id : 0u,
                        x,
                        y,
                        width,
                        height,
                        (unsigned)pixels->stride);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }

    *wrote = 0;
    tile_right = x + width;
    tile_bottom = y + height;
    for (i = 0; i < region->rect_count; i++)
    {
        rdp_graphics_rect16 rect;
        uint32_t left = 0;
        uint32_t top = 0;
        uint32_t right = 0;
        uint32_t bottom = 0;
        const uint8_t* src = NULL;

        status = rdp_graphics_progressive_parse_region_rect(region->rects + ((size_t)i * 8u),
                                                            region->rects_len - ((size_t)i * 8u),
                                                            &rect);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.progressive.write_region.failed",
                            "stage=rect_parse surface_id=%u tile_x=%u tile_y=%u tile_width=%u tile_height=%u rect_index=%u status=%d",
                            surface->surface_id,
                            x,
                            y,
                            width,
                            height,
                            i,
                            (int)status);
            return status;
        }
        if (rect.right <= rect.left || rect.bottom <= rect.top)
            continue;

        left = rdp_session_max_u32(x, rect.left);
        top = rdp_session_max_u32(y, rect.top);
        right = rdp_session_min_u32(tile_right, rect.right);
        bottom = rdp_session_min_u32(tile_bottom, rect.bottom);
        if (right <= left || bottom <= top)
            continue;

        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.region.write",
                        "surface_id=%u tile_x=%u tile_y=%u tile_width=%u tile_height=%u rect_index=%u rect_left=%u rect_top=%u rect_right=%u rect_bottom=%u write_left=%u write_top=%u write_width=%u write_height=%u frame_id=%u",
                        surface->surface_id,
                        x,
                        y,
                        width,
                        height,
                        i,
                        rect.left,
                        rect.top,
                        rect.right,
                        rect.bottom,
                        left,
                        top,
                        right - left,
                        bottom - top,
                        session->graphics_current_frame_id);
        src = pixels->bgra + (((size_t)top - y) * pixels->stride) + (((size_t)left - x) * 4u);
        status = rdp_session_graphics_surface_write_bgra(session,
                                                         surface,
                                                         (uint16_t)left,
                                                         (uint16_t)top,
                                                         (uint16_t)(right - left),
                                                         (uint16_t)(bottom - top),
                                                         src,
                                                         pixels->stride,
                                                         0,
                                                         "progressive");
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.progressive.write_region.failed",
                            "stage=surface_write surface_id=%u surface_width=%u surface_height=%u tile_x=%u tile_y=%u tile_width=%u tile_height=%u rect_left=%u rect_top=%u rect_right=%u rect_bottom=%u write_left=%u write_top=%u write_width=%u write_height=%u stride=%u status=%d",
                            surface->surface_id,
                            surface->width,
                            surface->height,
                            x,
                            y,
                            width,
                            height,
                            rect.left,
                            rect.top,
                            rect.right,
                            rect.bottom,
                            left,
                            top,
                            right - left,
                            bottom - top,
                            (unsigned)pixels->stride,
                            (int)status);
            return status;
        }
        *wrote = 1;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_progressive_render_tile(librdp_session* session,
                                                                  uint32_t channel_id,
                                                                  uint32_t codec_context_id,
                                                                  rdp_session_graphics_surface* surface,
                                                                  const rdp_graphics_progressive_region* region,
                                                                  uint16_t block_type,
                                                                  uint8_t quant_idx_y,
                                                                  uint8_t quant_idx_cb,
                                                                  uint8_t quant_idx_cr,
                                                                  uint16_t x_idx,
                                                                  uint16_t y_idx,
                                                                  uint8_t tile_flags,
                                                                  uint8_t progressive_idx,
                                                                  const uint8_t* y_data,
                                                                  size_t y_len,
                                                                  const uint8_t* cb_data,
                                                                  size_t cb_len,
                                                                  const uint8_t* cr_data,
                                                                  size_t cr_len,
                                                                  uint32_t* rendered_tiles,
                                                                  uint32_t* failed_tiles,
                                                                  uint32_t* unsupported_tiles)
{
    rdp_session_progressive_tile_cache* tile_cache = NULL;
    rdp_rfx_component_quant y_quant;
    rdp_rfx_component_quant y_delta;
    rdp_rfx_component_quant cb_quant;
    rdp_rfx_component_quant cb_delta;
    rdp_rfx_component_quant cr_quant;
    rdp_rfx_component_quant cr_delta;
    rdp_rfx_tile_pixels pixels;
    uint32_t x = (uint32_t)x_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    uint32_t y = (uint32_t)y_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    uint32_t width = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    uint32_t height = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    int extrapolate = 0;
    int wrote = 0;
    const char* stage = "base_quant.y";
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !region || !rendered_tiles || !failed_tiles || !unsupported_tiles)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!y_data || !cb_data || !cr_data)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (x >= surface->width || y >= surface->height)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.clipped",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        block_type);
        return LIBRDP_STATUS_OK;
    }
    if (width > (uint32_t)surface->width - x)
        width = (uint32_t)surface->width - x;
    if (height > (uint32_t)surface->height - y)
        height = (uint32_t)surface->height - y;

    stage = "base_quant.y";
    status = rdp_session_graphics_progressive_base_quant(region, quant_idx_y, &y_quant);
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.y";
        status = rdp_session_graphics_progressive_delta_quant(region, progressive_idx, 0, &y_delta);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "base_quant.cb";
        status = rdp_session_graphics_progressive_base_quant(region, quant_idx_cb, &cb_quant);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.cb";
        status = rdp_session_graphics_progressive_delta_quant(region, progressive_idx, 1, &cb_delta);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "base_quant.cr";
        status = rdp_session_graphics_progressive_base_quant(region, quant_idx_cr, &cr_quant);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.cr";
        status = rdp_session_graphics_progressive_delta_quant(region, progressive_idx, 2, &cr_delta);
    }
    extrapolate = (region->flags & 0x01u) != 0;
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "state";
        tile_cache = rdp_session_progressive_tile_get(session,
                                                      surface->surface_id,
                                                      x_idx,
                                                      y_idx,
                                                      1);
        if (!tile_cache || !tile_cache->state)
            status = LIBRDP_STATUS_NO_MEMORY;
    }
    if (status == LIBRDP_STATUS_OK &&
        (tile_flags & 0x01u) != 0 &&
        (!tile_cache->state->valid ||
         !tile_cache->state->y.valid ||
         !tile_cache->state->cb.valid ||
         !tile_cache->state->cr.valid))
    {
        (*unsupported_tiles)++;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.missing",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u flags=%u progressive_idx=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        block_type,
                        tile_flags,
                        progressive_idx);
        return LIBRDP_STATUS_OK;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "decode";
        status = rdp_rfx_decode_progressive_tile_state(y_data,
                                                       y_len,
                                                       cb_data,
                                                       cb_len,
                                                       cr_data,
                                                       cr_len,
                                                       &y_quant,
                                                       &y_delta,
                                                       &cb_quant,
                                                       &cb_delta,
                                                       &cr_quant,
                                                       &cr_delta,
                                                       extrapolate,
                                                       (tile_flags & 0x01u) != 0,
                                                       tile_cache->state,
                                                       &pixels);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        tile_cache->state->x_idx = x_idx;
        tile_cache->state->y_idx = y_idx;
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "write_region";
        status = rdp_session_graphics_progressive_write_region_tile(session,
                                                                    surface,
                                                                    region,
                                                                    x,
                                                                    y,
                                                                    width,
                                                                    height,
                                                                    &pixels,
                                                                    &wrote);
    }
    if (status != LIBRDP_STATUS_OK)
    {
        (*failed_tiles)++;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.failed",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u flags=%u progressive_idx=%u stage=%s status=%d y_len=%u cb_len=%u cr_len=%u extrapolate=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        block_type,
                        tile_flags,
                        progressive_idx,
                        stage,
                        (int)status,
                        (unsigned)y_len,
                        (unsigned)cb_len,
                        (unsigned)cr_len,
                        (unsigned)extrapolate);
        return LIBRDP_STATUS_OK;
    }

    if (!wrote)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.region_clipped",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u flags=%u progressive_idx=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        block_type,
                        tile_flags,
                        progressive_idx);
        return LIBRDP_STATUS_OK;
    }

    (*rendered_tiles)++;
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.graphics.progressive.tile",
                    "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u width=%u height=%u block_type=%u flags=%u progressive_idx=%u pass=%u extrapolate=%u",
                    channel_id,
                    codec_context_id,
                    surface->surface_id,
                    x,
                    y,
                    width,
                    height,
                    block_type,
                    tile_flags,
                    progressive_idx,
                    tile_cache && tile_cache->state ? tile_cache->state->pass : 0u,
                    (unsigned)extrapolate);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_progressive_render_upgrade(
    librdp_session* session,
    uint32_t channel_id,
    uint32_t codec_context_id,
    rdp_session_graphics_surface* surface,
    const rdp_graphics_progressive_region* region,
    const rdp_graphics_progressive_tile_upgrade* tile,
    uint32_t* rendered_tiles,
    uint32_t* failed_tiles,
    uint32_t* unsupported_tiles)
{
    rdp_session_progressive_tile_cache* tile_cache = NULL;
    rdp_rfx_component_quant y_quant;
    rdp_rfx_component_quant y_delta;
    rdp_rfx_component_quant cb_quant;
    rdp_rfx_component_quant cb_delta;
    rdp_rfx_component_quant cr_quant;
    rdp_rfx_component_quant cr_delta;
    rdp_rfx_tile_pixels pixels;
    uint32_t x = 0;
    uint32_t y = 0;
    uint32_t width = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    uint32_t height = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    int extrapolate = 0;
    int wrote = 0;
    const char* stage = "state";
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface || !region || !tile || !rendered_tiles || !failed_tiles || !unsupported_tiles)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    x = (uint32_t)tile->x_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    y = (uint32_t)tile->y_idx * RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    if (x >= surface->width || y >= surface->height)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.clipped",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        tile->block_type);
        return LIBRDP_STATUS_OK;
    }
    if (width > (uint32_t)surface->width - x)
        width = (uint32_t)surface->width - x;
    if (height > (uint32_t)surface->height - y)
        height = (uint32_t)surface->height - y;

    tile_cache = rdp_session_progressive_tile_get(session,
                                                  surface->surface_id,
                                                  tile->x_idx,
                                                  tile->y_idx,
                                                  0);
    if (!tile_cache || !tile_cache->state || !tile_cache->state->valid)
    {
        (*unsupported_tiles)++;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.missing",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u progressive_idx=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        tile->block_type,
                        tile->progressive_quality);
        return LIBRDP_STATUS_OK;
    }

    stage = "base_quant.y";
    status = rdp_session_graphics_progressive_base_quant(region, tile->quant_idx_y, &y_quant);
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.y";
        status = rdp_session_graphics_progressive_delta_quant(region, tile->progressive_quality, 0, &y_delta);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "base_quant.cb";
        status = rdp_session_graphics_progressive_base_quant(region, tile->quant_idx_cb, &cb_quant);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.cb";
        status = rdp_session_graphics_progressive_delta_quant(region, tile->progressive_quality, 1, &cb_delta);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "base_quant.cr";
        status = rdp_session_graphics_progressive_base_quant(region, tile->quant_idx_cr, &cr_quant);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "delta_quant.cr";
        status = rdp_session_graphics_progressive_delta_quant(region, tile->progressive_quality, 2, &cr_delta);
    }

    extrapolate = (region->flags & 0x01u) != 0;
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "decode";
        status = rdp_rfx_decode_progressive_upgrade_tile(tile->y_srl_data,
                                                         tile->y_srl_len,
                                                         tile->y_raw_data,
                                                         tile->y_raw_len,
                                                         tile->cb_srl_data,
                                                         tile->cb_srl_len,
                                                         tile->cb_raw_data,
                                                         tile->cb_raw_len,
                                                         tile->cr_srl_data,
                                                         tile->cr_srl_len,
                                                         tile->cr_raw_data,
                                                         tile->cr_raw_len,
                                                         &y_quant,
                                                         &y_delta,
                                                         &cb_quant,
                                                         &cb_delta,
                                                         &cr_quant,
                                                         &cr_delta,
                                                         extrapolate,
                                                         tile_cache->state,
                                                         &pixels);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        stage = "write_region";
        status = rdp_session_graphics_progressive_write_region_tile(session,
                                                                    surface,
                                                                    region,
                                                                    x,
                                                                    y,
                                                                    width,
                                                                    height,
                                                                    &pixels,
                                                                    &wrote);
    }
    if (status != LIBRDP_STATUS_OK)
    {
        (*failed_tiles)++;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.failed",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u stage=%s status=%d y_srl_len=%u y_raw_len=%u cb_srl_len=%u cb_raw_len=%u cr_srl_len=%u cr_raw_len=%u extrapolate=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        tile->block_type,
                        stage,
                        (int)status,
                        tile->y_srl_len,
                        tile->y_raw_len,
                        tile->cb_srl_len,
                        tile->cb_raw_len,
                        tile->cr_srl_len,
                        tile->cr_raw_len,
                        (unsigned)extrapolate);
        return LIBRDP_STATUS_OK;
    }

    if (!wrote)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.progressive.tile.region_clipped",
                        "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u block_type=%u progressive_idx=%u",
                        channel_id,
                        codec_context_id,
                        surface->surface_id,
                        x,
                        y,
                        tile->block_type,
                        tile->progressive_quality);
        return LIBRDP_STATUS_OK;
    }

    (*rendered_tiles)++;
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.graphics.progressive.tile",
                    "dvc_channel_id=%u context_id=%u surface_id=%u x=%u y=%u width=%u height=%u block_type=%u progressive_idx=%u pass=%u extrapolate=%u",
                    channel_id,
                    codec_context_id,
                    surface->surface_id,
                    x,
                    y,
                    width,
                    height,
                    tile->block_type,
                    tile->progressive_quality,
                    tile_cache->state->pass,
                    (unsigned)extrapolate);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_progressive_render_region(librdp_session* session,
                                                                    uint32_t channel_id,
                                                                    uint32_t codec_context_id,
                                                                    rdp_session_graphics_surface* surface,
                                                                    const rdp_graphics_progressive_region* region,
                                                                    uint32_t* rendered_tiles,
                                                                    uint32_t* failed_tiles,
                                                                    uint32_t* unsupported_tiles)
{
    size_t offset = 0;

    if (!session || !surface || !region || !rendered_tiles || !failed_tiles || !unsupported_tiles)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    while (offset < region->tiles_len)
    {
        rdp_graphics_progressive_block block;
        librdp_status status = rdp_graphics_progressive_parse_block(region->tiles + offset,
                                                                    region->tiles_len - offset,
                                                                    &block);

        if (status != LIBRDP_STATUS_OK)
            return status;
        if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_SIMPLE)
        {
            rdp_graphics_progressive_tile_simple tile;

            status = rdp_graphics_progressive_parse_tile_simple(region->tiles + offset,
                                                                region->tiles_len - offset,
                                                                &tile);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_graphics_progressive_render_tile(session,
                                                                  channel_id,
                                                                  codec_context_id,
                                                                  surface,
                                                                  region,
                                                                  block.type,
                                                                  tile.quant_idx_y,
                                                                  tile.quant_idx_cb,
                                                                  tile.quant_idx_cr,
                                                                  tile.x_idx,
                                                                  tile.y_idx,
                                                                  tile.flags,
                                                                  0xffu,
                                                                  tile.y_data,
                                                                  tile.y_len,
                                                                  tile.cb_data,
                                                                  tile.cb_len,
                                                                  tile.cr_data,
                                                                  tile.cr_len,
                                                                  rendered_tiles,
                                                                  failed_tiles,
                                                                  unsupported_tiles);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_FIRST)
        {
            rdp_graphics_progressive_tile_first tile;

            status = rdp_graphics_progressive_parse_tile_first(region->tiles + offset,
                                                               region->tiles_len - offset,
                                                               &tile);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_graphics_progressive_render_tile(session,
                                                                  channel_id,
                                                                  codec_context_id,
                                                                  surface,
                                                                  region,
                                                                  block.type,
                                                                  tile.quant_idx_y,
                                                                  tile.quant_idx_cb,
                                                                  tile.quant_idx_cr,
                                                                  tile.x_idx,
                                                                  tile.y_idx,
                                                                  tile.flags,
                                                                  tile.progressive_quality,
                                                                  tile.y_data,
                                                                  tile.y_len,
                                                                  tile.cb_data,
                                                                  tile.cb_len,
                                                                  tile.cr_data,
                                                                  tile.cr_len,
                                                                  rendered_tiles,
                                                                  failed_tiles,
                                                                  unsupported_tiles);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_UPGRADE)
        {
            rdp_graphics_progressive_tile_upgrade tile;

            status = rdp_graphics_progressive_parse_tile_upgrade(region->tiles + offset,
                                                                 region->tiles_len - offset,
                                                                 &tile);
            if (status != LIBRDP_STATUS_OK)
                return status;
            status = rdp_session_graphics_progressive_render_upgrade(session,
                                                                     channel_id,
                                                                     codec_context_id,
                                                                     surface,
                                                                     region,
                                                                     &tile,
                                                                     rendered_tiles,
                                                                     failed_tiles,
                                                                     unsupported_tiles);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else
        {
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        }
        offset += block.length;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_progressive_render_stream(librdp_session* session,
                                                                    uint32_t channel_id,
                                                                    rdp_session_graphics_surface* surface,
                                                                    const rdp_graphics_wire_to_surface_2* wire,
                                                                    uint32_t* rendered_tiles,
                                                                    uint32_t* failed_tiles,
                                                                    uint32_t* unsupported_tiles)
{
    size_t offset = 0;
    uint32_t region_index = 0;

    if (!session || !surface || !wire || !rendered_tiles || !failed_tiles || !unsupported_tiles)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    *rendered_tiles = 0;
    *failed_tiles = 0;
    *unsupported_tiles = 0;
    while (offset < wire->bitmap_data_length)
    {
        rdp_graphics_progressive_block block;
        librdp_status status = rdp_graphics_progressive_parse_block(wire->bitmap_data + offset,
                                                                    wire->bitmap_data_length - offset,
                                                                    &block);

        if (status != LIBRDP_STATUS_OK)
            return status;
        if (block.type == RDP_GRAPHICS_PROGRESSIVE_BLOCK_REGION)
        {
            rdp_graphics_progressive_region region;

            status = rdp_graphics_progressive_parse_region(wire->bitmap_data + offset,
                                                           wire->bitmap_data_length - offset,
                                                           &region);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.progressive.region",
                            "dvc_channel_id=%u context_id=%u surface_id=%u region_index=%u rect_count=%u quant_count=%u progressive_quant_count=%u tile_count=%u tile_data_size=%u flags=%u tile_size=%u frame_id=%u",
                            channel_id,
                            wire->codec_context_id,
                            surface->surface_id,
                            region_index,
                            region.rect_count,
                            region.quant_count,
                            region.progressive_quant_count,
                            region.tile_count,
                            region.tile_data_size,
                            region.flags,
                            region.tile_size,
                            session->graphics_current_frame_id);
            status = rdp_session_graphics_progressive_render_region(session,
                                                                    channel_id,
                                                                    wire->codec_context_id,
                                                                    surface,
                                                                    &region,
                                                                    rendered_tiles,
                                                                    failed_tiles,
                                                                    unsupported_tiles);
            if (status != LIBRDP_STATUS_OK)
                return status;
            region_index++;
        }
        offset += block.length;
    }
    return LIBRDP_STATUS_OK;
}

static void rdp_session_graphics_cache_evict(librdp_session* session, uint16_t cache_slot)
{
    rdp_session_graphics_cache_entry* entry = NULL;

    if (!session || cache_slot >= RDP_SESSION_GRAPHICS_CACHE_SLOTS)
        return;
    entry = &session->graphics_cache[cache_slot];
    if (entry->active)
    {
        if (session->graphics_cache_bytes >= entry->pixels.length)
            session->graphics_cache_bytes -= entry->pixels.length;
        else
            session->graphics_cache_bytes = 0;
    }
    rdp_buffer_free(&entry->pixels);
    memset(entry, 0, sizeof(*entry));
}

static void rdp_session_graphics_cache_clear(librdp_session* session)
{
    size_t i = 0;

    if (!session)
        return;
    for (i = 0; i < RDP_SESSION_GRAPHICS_CACHE_SLOTS; i++)
        rdp_buffer_free(&session->graphics_cache[i].pixels);
    memset(session->graphics_cache, 0, sizeof(session->graphics_cache));
    session->graphics_cache_bytes = 0;
}

static rdp_session_graphics_cache_entry* rdp_session_graphics_cache_find(librdp_session* session, uint16_t cache_slot)
{
    if (!session || cache_slot >= RDP_SESSION_GRAPHICS_CACHE_SLOTS || !session->graphics_cache[cache_slot].active)
        return NULL;
    return &session->graphics_cache[cache_slot];
}

static librdp_status rdp_session_graphics_cache_store(librdp_session* session,
                                                      const rdp_graphics_surface_to_cache* surface_to_cache)
{
    rdp_session_graphics_surface* surface = NULL;
    rdp_session_graphics_cache_entry* entry = NULL;
    uint16_t width = 0;
    uint16_t height = 0;
    size_t source_stride = 0;
    size_t size = 0;
    size_t old_size = 0;
    size_t current_without_old = 0;
    uint16_t row = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !surface_to_cache)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (surface_to_cache->cache_slot >= RDP_SESSION_GRAPHICS_CACHE_SLOTS)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    surface = rdp_session_graphics_surface_find(session, surface_to_cache->surface_id);
    if (!surface)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    if (surface_to_cache->rect_src.right > surface->width ||
        surface_to_cache->rect_src.bottom > surface->height ||
        surface_to_cache->rect_src.left >= surface_to_cache->rect_src.right ||
        surface_to_cache->rect_src.top >= surface_to_cache->rect_src.bottom)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    width = (uint16_t)(surface_to_cache->rect_src.right - surface_to_cache->rect_src.left);
    height = (uint16_t)(surface_to_cache->rect_src.bottom - surface_to_cache->rect_src.top);
    size = (size_t)width * (size_t)height * 4u;
    entry = &session->graphics_cache[surface_to_cache->cache_slot];
    old_size = entry->active ? entry->pixels.length : 0;
    current_without_old = session->graphics_cache_bytes >= old_size ? session->graphics_cache_bytes - old_size : 0;
    if (size > RDP_SESSION_GRAPHICS_CACHE_MAX_BYTES ||
        current_without_old > RDP_SESSION_GRAPHICS_CACHE_MAX_BYTES - size)
        return LIBRDP_STATUS_NO_MEMORY;

    status = rdp_buffer_reserve(&entry->pixels, size);
    if (status != LIBRDP_STATUS_OK)
        return status;

    source_stride = (size_t)surface->width * 4u;
    for (row = 0; row < height; row++)
    {
        memcpy(entry->pixels.data + ((size_t)row * (size_t)width * 4u),
               surface->pixels.data + ((size_t)(surface_to_cache->rect_src.top + row) * source_stride) +
                   ((size_t)surface_to_cache->rect_src.left * 4u),
               (size_t)width * 4u);
    }
    entry->pixels.length = size;
    entry->active = 1;
    entry->cache_slot = surface_to_cache->cache_slot;
    entry->width = width;
    entry->height = height;
    entry->cache_key = surface_to_cache->cache_key;
    session->graphics_cache_bytes = current_without_old + size;
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.graphics.cache.store",
                    "surface_id=%u cache_slot=%u width=%u height=%u src_left=%u src_top=%u src_right=%u src_bottom=%u cache_key=%llu cache_bytes=%llu source_hash=%016llx cache_hash=%016llx frame_id=%u",
                    surface_to_cache->surface_id,
                    surface_to_cache->cache_slot,
                    width,
                    height,
                    surface_to_cache->rect_src.left,
                    surface_to_cache->rect_src.top,
                    surface_to_cache->rect_src.right,
                    surface_to_cache->rect_src.bottom,
                    (unsigned long long)surface_to_cache->cache_key,
                    (unsigned long long)session->graphics_cache_bytes,
                    (unsigned long long)rdp_session_trace_surface_hash(surface,
                                                                        surface_to_cache->rect_src.left,
                                                                        surface_to_cache->rect_src.top,
                                                                        width,
                                                                        height),
                    (unsigned long long)rdp_session_trace_hash_bgra(entry->pixels.data,
                                                                    width,
                                                                    height,
                                                                    (size_t)width * 4u),
                    session->graphics_current_frame_id);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_graphics_surface_copy(librdp_session* session,
                                                       rdp_session_graphics_surface* source,
                                                       rdp_session_graphics_surface* dest,
                                                       const rdp_graphics_rect16* rect,
                                                       const rdp_graphics_point16* point)
{
    rdp_buffer copy;
    uint16_t width = 0;
    uint16_t height = 0;
    size_t source_stride = 0;
    size_t row_stride = 0;
    uint16_t row = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !source || !dest || !rect || !point || !source->active || !dest->active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (rect->right > source->width || rect->bottom > source->height ||
        rect->left >= rect->right || rect->top >= rect->bottom)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    width = (uint16_t)(rect->right - rect->left);
    height = (uint16_t)(rect->bottom - rect->top);
    if (point->x > dest->width || point->y > dest->height ||
        width > dest->width - point->x || height > dest->height - point->y)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    rdp_buffer_init(&copy);
    row_stride = (size_t)width * 4u;
    status = rdp_buffer_reserve(&copy, row_stride * (size_t)height);
    if (status == LIBRDP_STATUS_OK)
    {
        source_stride = (size_t)source->width * 4u;
        for (row = 0; row < height; row++)
        {
            memcpy(copy.data + ((size_t)row * row_stride),
                   source->pixels.data + ((size_t)(rect->top + row) * source_stride) + ((size_t)rect->left * 4u),
                   row_stride);
        }
        copy.length = row_stride * (size_t)height;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.surface.copy",
                        "source_id=%u dest_id=%u src_left=%u src_top=%u src_right=%u src_bottom=%u dst_x=%u dst_y=%u width=%u height=%u frame_id=%u copy_hash=%016llx",
                        source->surface_id,
                        dest->surface_id,
                        rect->left,
                        rect->top,
                        rect->right,
                        rect->bottom,
                        point->x,
                        point->y,
                        width,
                        height,
                        session->graphics_current_frame_id,
                        (unsigned long long)rdp_session_trace_hash_bgra(copy.data, width, height, row_stride));
        status = rdp_session_graphics_surface_write_bgra(session,
                                                         dest,
                                                         point->x,
                                                         point->y,
                                                         width,
                                                         height,
                                                         copy.data,
                                                         row_stride,
                                                         0,
                                                         "surface_to_surface");
    }
    rdp_buffer_free(&copy);
    return status;
}

static librdp_status rdp_session_graphics_cache_copy_to_surface(librdp_session* session,
                                                                rdp_session_graphics_cache_entry* cache,
                                                                rdp_session_graphics_surface* surface,
                                                                const rdp_graphics_point16* point)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !cache || !surface || !point || !cache->active || !surface->active)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (point->x > surface->width || point->y > surface->height ||
        cache->width > surface->width - point->x || cache->height > surface->height - point->y)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.graphics.cache.copy",
                    "cache_slot=%u surface_id=%u dst_x=%u dst_y=%u width=%u height=%u cache_key=%llu frame_id=%u cache_hash=%016llx",
                    cache->cache_slot,
                    surface->surface_id,
                    point->x,
                    point->y,
                    cache->width,
                    cache->height,
                    (unsigned long long)cache->cache_key,
                    session->graphics_current_frame_id,
                    (unsigned long long)rdp_session_trace_hash_bgra(cache->pixels.data,
                                                                    cache->width,
                                                                    cache->height,
                                                                    (size_t)cache->width * 4u));
    status = rdp_session_graphics_surface_write_bgra(session,
                                                     surface,
                                                     point->x,
                                                     point->y,
                                                     cache->width,
                                                     cache->height,
                                                     cache->pixels.data,
                                                     (size_t)cache->width * 4u,
                                                     0,
                                                     "cache_to_surface");
    return status;
}

static librdp_status rdp_session_read_mcs_pdu(librdp_session* session,
                                              rdp_buffer* packet,
                                              const uint8_t** pdu,
                                              size_t* pdu_len,
                                              const char* event);

static librdp_status rdp_session_send_display_control_layout(librdp_session* session,
                                                             uint32_t width,
                                                             uint32_t height)
{
    rdp_display_control_monitor monitor;
    rdp_buffer layout;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!session->display_control_ready || session->display_control_channel_id_bytes == 0)
        return LIBRDP_STATUS_STATE;
    if (session->sent_desktop_width == width && session->sent_desktop_height == height)
        return LIBRDP_STATUS_OK;

    rdp_buffer_init(&layout);
    status = rdp_display_control_make_single_monitor(&monitor, width, height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_display_control_write_monitor_layout(&layout, &monitor, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->display_control_channel_id,
                                                       session->display_control_channel_id_bytes,
                                                       layout.data,
                                                       layout.length,
                                                       "client.display_control.layout_sent");
    rdp_buffer_free(&layout);
    if (status == LIBRDP_STATUS_OK)
    {
        session->sent_desktop_width = width;
        session->sent_desktop_height = height;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.display_control.layout_sent",
                        "dvc_channel_id=%u width=%u height=%u",
                        session->display_control_channel_id,
                        width,
                        height);
    }
    return status;
}

static librdp_status rdp_session_request_display_control_layout(librdp_session* session,
                                                                uint32_t width,
                                                                uint32_t height)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || width == 0 || height == 0 || width > 8192u || height > 8192u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    session->requested_desktop_width = width;
    session->requested_desktop_height = height;
    status = rdp_session_send_display_control_layout(session, width, height);
    if (status == LIBRDP_STATUS_STATE)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.display_control.layout.local",
                        "width=%u height=%u wire=not_sent",
                        width,
                        height);
        return LIBRDP_STATUS_OK;
    }
    return status;
}

static librdp_status rdp_session_send_core_input_init(librdp_session* session)
{
    rdp_buffer request;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || session->core_input_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&request);
    status = rdp_core_input_write_init_request(&request);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->core_input_channel_id,
                                                       session->core_input_channel_id_bytes,
                                                       request.data,
                                                       request.length,
                                                       "client.core_input.init");
    rdp_buffer_free(&request);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.core_input.init",
                        "dvc_channel_id=%u version=%u",
                        session->core_input_channel_id,
                        RDP_CORE_INPUT_PROTOCOL_VERSION_100);
    return status;
}

static librdp_status rdp_session_send_mouse_cursor_caps(librdp_session* session)
{
    rdp_buffer caps;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || session->mouse_cursor_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&caps);
    status = rdp_mouse_cursor_write_caps_advertise(&caps);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->mouse_cursor_channel_id,
                                                       session->mouse_cursor_channel_id_bytes,
                                                       caps.data,
                                                       caps.length,
                                                       "client.mouse_cursor.caps_advertise");
    rdp_buffer_free(&caps);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.mouse_cursor.caps_advertise",
                        "dvc_channel_id=%u version=%u",
                        session->mouse_cursor_channel_id,
                        RDP_MOUSE_CURSOR_CAPSET_VERSION1);
    return status;
}

static librdp_status rdp_session_send_graphics_caps(librdp_session* session)
{
    rdp_buffer caps;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || session->graphics_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&caps);
    status = rdp_graphics_write_default_caps_advertise(&caps);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->graphics_channel_id,
                                                       session->graphics_channel_id_bytes,
                                                       caps.data,
                                                       caps.length,
                                                       "client.graphics.caps_advertise");
    rdp_buffer_free(&caps);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.caps_advertise",
                        "dvc_channel_id=%u",
                        session->graphics_channel_id);
    return status;
}

static librdp_status rdp_session_send_graphics_frame_ack(librdp_session* session, uint32_t frame_id)
{
    rdp_buffer ack;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || session->graphics_channel_id_bytes == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&ack);
    status = rdp_graphics_write_frame_ack(&ack,
                                          RDP_GRAPHICS_QUEUE_DEPTH_UNAVAILABLE,
                                          frame_id,
                                          session->graphics_frames_decoded);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_send_dynamic_channel_data(session,
                                                       session->graphics_channel_id,
                                                       session->graphics_channel_id_bytes,
                                                       ack.data,
                                                       ack.length,
                                                       "client.graphics.frame_ack");
    rdp_buffer_free(&ack);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.frame_ack",
                        "dvc_channel_id=%u frame_id=%u total_frames_decoded=%u",
                        session->graphics_channel_id,
                        frame_id,
                        session->graphics_frames_decoded);
    return status;
}

static librdp_status rdp_session_handle_graphics_message(librdp_session* session,
                                                         uint32_t channel_id,
                                                         const uint8_t* data,
                                                         size_t data_len)
{
    rdp_buffer decoded;
    size_t offset = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&decoded);
    status = rdp_graphics_decode_segmented_data(&session->graphics_decompressor, data, data_len, &decoded);
    if (status == LIBRDP_STATUS_UNSUPPORTED)
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.graphics.unsupported",
                        "dvc_channel_id=%u reason=bulk_compression payload_len=%u",
                        channel_id,
                        (unsigned)data_len);
        rdp_buffer_free(&decoded);
        return LIBRDP_STATUS_OK;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&decoded);
        return status;
    }

    while (offset < decoded.length)
    {
        rdp_graphics_header header;
        const uint8_t* pdu = decoded.data + offset;
        size_t remaining = decoded.length - offset;

        status = rdp_graphics_parse_header(pdu, remaining, &header);
        if (status != LIBRDP_STATUS_OK)
            break;
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "rdp.graphics.pdu",
                        "dvc_channel_id=%u cmd_id=%u pdu_len=%u",
                        channel_id,
                        header.cmd_id,
                        header.pdu_length);
        rdp_trace_hexdump("rdp.graphics.pdu", pdu, header.pdu_length);
        if (header.cmd_id == RDP_GRAPHICS_CMDID_CAPS_CONFIRM)
        {
            rdp_graphics_caps_confirm confirm;

            status = rdp_graphics_parse_caps_confirm(pdu, header.pdu_length, &confirm);
            if (status != LIBRDP_STATUS_OK)
                break;
            session->graphics_selected_version = confirm.selected.version;
            session->graphics_selected_flags = confirm.selected.flags;
            session->graphics_ready = 1;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.caps_confirm",
                            "dvc_channel_id=%u version=%u flags=%u",
                            channel_id,
                            confirm.selected.version,
                            confirm.selected.flags);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_WIRE_TO_SURFACE_1)
        {
            rdp_graphics_wire_to_surface_1 wire;

            status = rdp_graphics_parse_wire_to_surface_1(pdu, header.pdu_length, &wire);
            if (status != LIBRDP_STATUS_OK)
                break;
            if (wire.codec_id == RDP_GRAPHICS_CODECID_UNCOMPRESSED ||
                wire.codec_id == RDP_GRAPHICS_CODECID_CLEARCODEC)
            {
                rdp_session_graphics_surface* surface = rdp_session_graphics_surface_find(session, wire.surface_id);
                int rendered = 0;

                if (!surface)
                {
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    break;
                }
                if (wire.codec_id == RDP_GRAPHICS_CODECID_UNCOMPRESSED)
                {
                    status = rdp_session_graphics_surface_write_wire(session, surface, &wire);
                    if (status != LIBRDP_STATUS_OK)
                        break;
                    rendered = 1;
                }
                else
                {
                    rdp_buffer decoded_bitmap;
                    size_t decoded_stride = 0;
                    uint16_t width = (uint16_t)(wire.dest_rect.right - wire.dest_rect.left);
                    uint16_t height = (uint16_t)(wire.dest_rect.bottom - wire.dest_rect.top);

                    rdp_buffer_init(&decoded_bitmap);
                    status = rdp_clearcodec_decode_bitmap(&session->clearcodec,
                                                          wire.bitmap_data,
                                                          wire.bitmap_data_length,
                                                          width,
                                                          height,
                                                          &decoded_bitmap,
                                                          &decoded_stride);
                    if (status == LIBRDP_STATUS_OK)
                        status = rdp_session_graphics_surface_write_bgra(session,
	                                                                         surface,
	                                                                         wire.dest_rect.left,
	                                                                         wire.dest_rect.top,
	                                                                         width,
	                                                                         height,
	                                                                         decoded_bitmap.data,
	                                                                         decoded_stride,
	                                                                         0,
	                                                                         "clearcodec");
                    rdp_buffer_free(&decoded_bitmap);
                    if (status == LIBRDP_STATUS_UNSUPPORTED || status == LIBRDP_STATUS_PROTOCOL_ERROR)
                    {
                        rdp_trace_event(RDP_TRACE_CLIENT,
                                        "client.graphics.clearcodec.unsupported",
                                        "dvc_channel_id=%u surface_id=%u payload_len=%u decoder_status=%d",
                                        channel_id,
                                        wire.surface_id,
                                        wire.bitmap_data_length,
                                        (int)status);
                        status = LIBRDP_STATUS_OK;
                    }
                    if (status != LIBRDP_STATUS_OK)
                        break;
                    if (decoded_stride != 0)
                        rendered = 1;
                }
                if (rendered)
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.graphics.wire_to_surface",
                                    "dvc_channel_id=%u surface_id=%u codec_id=%u x=%u y=%u width=%u height=%u",
                                    channel_id,
                                    wire.surface_id,
                                    wire.codec_id,
                                    wire.dest_rect.left,
                                    wire.dest_rect.top,
                                    (unsigned)(wire.dest_rect.right - wire.dest_rect.left),
                                    (unsigned)(wire.dest_rect.bottom - wire.dest_rect.top));
            }
            else
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.graphics.wire_to_surface.unsupported",
                                "dvc_channel_id=%u surface_id=%u codec_id=%u payload_len=%u",
                                channel_id,
                                wire.surface_id,
                                wire.codec_id,
                                wire.bitmap_data_length);
            }
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_WIRE_TO_SURFACE_2)
        {
            rdp_graphics_wire_to_surface_2 wire;

            status = rdp_graphics_parse_wire_to_surface_2(pdu, header.pdu_length, &wire);
            if (status != LIBRDP_STATUS_OK)
                break;
            if (wire.codec_id == RDP_GRAPHICS_CODECID_CAPROGRESSIVE)
            {
                rdp_session_graphics_surface* surface = rdp_session_graphics_surface_find(session, wire.surface_id);
                rdp_graphics_progressive_stream progressive;
                uint32_t rendered_tiles = 0;
                uint32_t failed_tiles = 0;
                uint32_t unsupported_tiles = 0;

                if (!surface)
                {
                    status = LIBRDP_STATUS_PROTOCOL_ERROR;
                    break;
                }
                status = rdp_graphics_progressive_parse_stream(wire.bitmap_data,
                                                               wire.bitmap_data_length,
                                                               &progressive);
                if (status == LIBRDP_STATUS_OK)
                {
                    status = rdp_session_graphics_progressive_render_stream(session,
                                                                           channel_id,
                                                                           surface,
                                                                           &wire,
                                                                           &rendered_tiles,
                                                                           &failed_tiles,
                                                                           &unsupported_tiles);
                    if (status != LIBRDP_STATUS_OK)
                        break;
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.graphics.progressive",
                                    "dvc_channel_id=%u surface_id=%u context_id=%u blocks=%u regions=%u tiles=%u simple_tiles=%u first_tiles=%u upgrade_tiles=%u rendered_tiles=%u failed_tiles=%u unsupported_tiles=%u",
                                    channel_id,
                                    wire.surface_id,
                                    wire.codec_context_id,
                                    progressive.block_count,
                                    progressive.region_count,
                                    progressive.tile_count,
                                    progressive.simple_tile_count,
                                    progressive.first_tile_count,
                                    progressive.upgrade_tile_count,
                                    rendered_tiles,
                                    failed_tiles,
                                    unsupported_tiles);
                }
                else
                {
                    rdp_trace_event(RDP_TRACE_CLIENT,
                                    "client.graphics.progressive.unsupported",
                                    "dvc_channel_id=%u surface_id=%u context_id=%u payload_len=%u parser_status=%d",
                                    channel_id,
                                    wire.surface_id,
                                    wire.codec_context_id,
                                    wire.bitmap_data_length,
                                    (int)status);
                    status = LIBRDP_STATUS_OK;
                }
            }
            else
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.graphics.wire_to_surface.unsupported",
                                "dvc_channel_id=%u surface_id=%u codec_id=%u context_id=%u payload_len=%u",
                                channel_id,
                                wire.surface_id,
                                wire.codec_id,
                                wire.codec_context_id,
                                wire.bitmap_data_length);
            }
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_DELETE_ENCODING_CONTEXT)
        {
            rdp_graphics_delete_encoding_context context;

            status = rdp_graphics_parse_delete_encoding_context(pdu, header.pdu_length, &context);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.encoding_context.delete",
                            "dvc_channel_id=%u surface_id=%u context_id=%u",
                            channel_id,
                            context.surface_id,
                            context.codec_context_id);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_SURFACE_TO_SURFACE)
        {
            rdp_graphics_surface_to_surface surface_to_surface;
            rdp_session_graphics_surface* source = NULL;
            rdp_session_graphics_surface* dest = NULL;
            rdp_graphics_point16 last_point;
            uint16_t i = 0;

            memset(&last_point, 0, sizeof(last_point));
            status = rdp_graphics_parse_surface_to_surface(pdu, header.pdu_length, &surface_to_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            source = rdp_session_graphics_surface_find(session, surface_to_surface.surface_id_src);
            dest = rdp_session_graphics_surface_find(session, surface_to_surface.surface_id_dest);
            if (!source || !dest)
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
            for (i = 0; i < surface_to_surface.dest_points_count; i++)
            {
                rdp_graphics_point16 point;

                status = rdp_graphics_parse_point16(surface_to_surface.dest_points + ((size_t)i * 4u),
                                                    surface_to_surface.dest_points_len - ((size_t)i * 4u),
                                                    &point);
                if (status == LIBRDP_STATUS_OK)
                {
                    status = rdp_session_graphics_surface_copy(session,
                                                               source,
                                                               dest,
                                                               &surface_to_surface.rect_src,
                                                               &point);
                    if (status == LIBRDP_STATUS_OK)
                        last_point = point;
                }
                if (status != LIBRDP_STATUS_OK)
                    break;
            }
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.surface_to_surface",
                            "dvc_channel_id=%u source_id=%u dest_id=%u points=%u src_left=%u src_top=%u src_right=%u src_bottom=%u last_dst_x=%u last_dst_y=%u",
                            channel_id,
                            surface_to_surface.surface_id_src,
                            surface_to_surface.surface_id_dest,
                            surface_to_surface.dest_points_count,
                            surface_to_surface.rect_src.left,
                            surface_to_surface.rect_src.top,
                            surface_to_surface.rect_src.right,
                            surface_to_surface.rect_src.bottom,
                            last_point.x,
                            last_point.y);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_SURFACE_TO_CACHE)
        {
            rdp_graphics_surface_to_cache surface_to_cache;

            status = rdp_graphics_parse_surface_to_cache(pdu, header.pdu_length, &surface_to_cache);
            if (status != LIBRDP_STATUS_OK)
                break;
            status = rdp_session_graphics_cache_store(session, &surface_to_cache);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.surface_to_cache",
                            "dvc_channel_id=%u surface_id=%u cache_slot=%u width=%u height=%u src_left=%u src_top=%u src_right=%u src_bottom=%u",
                            channel_id,
                            surface_to_cache.surface_id,
                            surface_to_cache.cache_slot,
                            (unsigned)(surface_to_cache.rect_src.right - surface_to_cache.rect_src.left),
                            (unsigned)(surface_to_cache.rect_src.bottom - surface_to_cache.rect_src.top),
                            surface_to_cache.rect_src.left,
                            surface_to_cache.rect_src.top,
                            surface_to_cache.rect_src.right,
                            surface_to_cache.rect_src.bottom);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_CACHE_TO_SURFACE)
        {
            rdp_graphics_cache_to_surface cache_to_surface;
            rdp_session_graphics_cache_entry* cache = NULL;
            rdp_session_graphics_surface* surface = NULL;
            rdp_graphics_point16 last_point;
            uint16_t i = 0;

            memset(&last_point, 0, sizeof(last_point));
            status = rdp_graphics_parse_cache_to_surface(pdu, header.pdu_length, &cache_to_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            cache = rdp_session_graphics_cache_find(session, cache_to_surface.cache_slot);
            surface = rdp_session_graphics_surface_find(session, cache_to_surface.surface_id);
            if (!cache || !surface)
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
            for (i = 0; i < cache_to_surface.dest_points_count; i++)
            {
                rdp_graphics_point16 point;

                status = rdp_graphics_parse_point16(cache_to_surface.dest_points + ((size_t)i * 4u),
                                                    cache_to_surface.dest_points_len - ((size_t)i * 4u),
                                                    &point);
                if (status == LIBRDP_STATUS_OK)
                {
                    status = rdp_session_graphics_cache_copy_to_surface(session, cache, surface, &point);
                    if (status == LIBRDP_STATUS_OK)
                        last_point = point;
                }
                if (status != LIBRDP_STATUS_OK)
                    break;
            }
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.cache_to_surface",
                            "dvc_channel_id=%u cache_slot=%u surface_id=%u points=%u cache_width=%u cache_height=%u last_dst_x=%u last_dst_y=%u",
                            channel_id,
                            cache_to_surface.cache_slot,
                            cache_to_surface.surface_id,
                            cache_to_surface.dest_points_count,
                            cache->width,
                            cache->height,
                            last_point.x,
                            last_point.y);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_EVICT_CACHE_ENTRY)
        {
            rdp_graphics_evict_cache_entry evict;

            status = rdp_graphics_parse_evict_cache_entry(pdu, header.pdu_length, &evict);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_session_graphics_cache_evict(session, evict.cache_slot);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.cache.evict",
                            "dvc_channel_id=%u cache_slot=%u",
                            channel_id,
                            evict.cache_slot);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_RESET_GRAPHICS)
        {
            rdp_graphics_reset reset;

            status = rdp_graphics_parse_reset(pdu, header.pdu_length, &reset);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_session_graphics_dirty_reset(session);
            rdp_session_graphics_surfaces_clear(session);
            if (reset.width != librdp_surface_width(session->surface) ||
                reset.height != librdp_surface_height(session->surface))
            {
                status = librdp_surface_resize(session->surface, reset.width, reset.height);
                if (status != LIBRDP_STATUS_OK)
                    break;
                rdp_session_emit_surface_invalidated(session, 0, 0, reset.width, reset.height);
            }
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.reset",
                            "dvc_channel_id=%u width=%u height=%u monitors=%u",
                            channel_id,
                            reset.width,
                            reset.height,
                            reset.monitor_count);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_CREATE_SURFACE)
        {
            rdp_graphics_create_surface create_surface;

            status = rdp_graphics_parse_create_surface(pdu, header.pdu_length, &create_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            status = rdp_session_graphics_surface_create(session, &create_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.surface.create",
                            "dvc_channel_id=%u surface_id=%u width=%u height=%u pixel_format=%u",
                            channel_id,
                            create_surface.surface_id,
                            create_surface.width,
                            create_surface.height,
                            create_surface.pixel_format);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_DELETE_SURFACE)
        {
            rdp_graphics_delete_surface delete_surface;

            status = rdp_graphics_parse_delete_surface(pdu, header.pdu_length, &delete_surface);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_session_graphics_surface_delete(session, delete_surface.surface_id);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.surface.delete",
                            "dvc_channel_id=%u surface_id=%u",
                            channel_id,
                            delete_surface.surface_id);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_MAP_SURFACE_TO_OUTPUT)
        {
            rdp_graphics_map_surface_to_output map;

            status = rdp_graphics_parse_map_surface_to_output(pdu, header.pdu_length, &map);
            if (status != LIBRDP_STATUS_OK)
                break;
            status = rdp_session_graphics_surface_map(session, &map);
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.surface.map_output",
                            "dvc_channel_id=%u surface_id=%u x=%u y=%u",
                            channel_id,
                            map.surface_id,
                            map.output_origin_x,
                            map.output_origin_y);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_MAP_SURFACE_TO_SCALED_OUTPUT)
        {
            rdp_graphics_map_surface_to_scaled_output map;
            rdp_session_graphics_surface* surface = NULL;

            status = rdp_graphics_parse_map_surface_to_scaled_output(pdu, header.pdu_length, &map);
            if (status != LIBRDP_STATUS_OK)
                break;
            surface = rdp_session_graphics_surface_find(session, map.surface_id);
            if (!surface)
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
            if (map.target_width == surface->width && map.target_height == surface->height)
            {
                rdp_graphics_map_surface_to_output unscaled_map;

                unscaled_map.surface_id = map.surface_id;
                unscaled_map.output_origin_x = map.output_origin_x;
                unscaled_map.output_origin_y = map.output_origin_y;
                status = rdp_session_graphics_surface_map(session, &unscaled_map);
                if (status != LIBRDP_STATUS_OK)
                    break;
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.graphics.surface.map_scaled_output",
                                "dvc_channel_id=%u surface_id=%u x=%u y=%u target_width=%u target_height=%u",
                                channel_id,
                                map.surface_id,
                                map.output_origin_x,
                                map.output_origin_y,
                                map.target_width,
                                map.target_height);
            }
            else
            {
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.graphics.surface.map_scaled_output.unsupported",
                                "dvc_channel_id=%u surface_id=%u x=%u y=%u target_width=%u target_height=%u",
                                channel_id,
                                map.surface_id,
                                map.output_origin_x,
                                map.output_origin_y,
                                map.target_width,
                                map.target_height);
            }
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_SOLIDFILL)
        {
            rdp_graphics_solid_fill solid_fill;
            rdp_session_graphics_surface* surface = NULL;
            uint16_t i = 0;

            status = rdp_graphics_parse_solid_fill(pdu, header.pdu_length, &solid_fill);
            if (status != LIBRDP_STATUS_OK)
                break;
            surface = rdp_session_graphics_surface_find(session, solid_fill.surface_id);
            if (!surface)
            {
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
                break;
            }
            for (i = 0; i < solid_fill.rect_count; i++)
            {
                rdp_graphics_rect16 rect;

                status = rdp_graphics_parse_rect16(solid_fill.rects + ((size_t)i * 8u),
                                                   solid_fill.rects_len - ((size_t)i * 8u),
                                                   &rect);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_graphics_surface_fill(session, surface, &rect, solid_fill.fill_pixel);
                if (status != LIBRDP_STATUS_OK)
                    break;
            }
            if (status != LIBRDP_STATUS_OK)
                break;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.solid_fill",
                            "dvc_channel_id=%u surface_id=%u rects=%u",
                            channel_id,
                            solid_fill.surface_id,
                            solid_fill.rect_count);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_START_FRAME)
        {
            rdp_graphics_start_frame start_frame;

            status = rdp_graphics_parse_start_frame(pdu, header.pdu_length, &start_frame);
            if (status != LIBRDP_STATUS_OK)
                break;
            if (session->graphics_frame_active)
                rdp_session_graphics_dirty_flush(session);
            session->graphics_frame_active = 1;
            session->graphics_current_frame_id = start_frame.frame_id;
            session->graphics_dirty_pending = 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.frame.start",
                            "dvc_channel_id=%u frame_id=%u timestamp=%u",
                            channel_id,
                            start_frame.frame_id,
                            start_frame.timestamp);
        }
        else if (header.cmd_id == RDP_GRAPHICS_CMDID_END_FRAME)
        {
            rdp_graphics_end_frame end_frame;

            status = rdp_graphics_parse_end_frame(pdu, header.pdu_length, &end_frame);
            if (status != LIBRDP_STATUS_OK)
                break;
            session->graphics_frame_active = 0;
            rdp_session_graphics_dirty_flush(session);
            session->graphics_frames_decoded++;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.frame.end",
                            "dvc_channel_id=%u frame_id=%u total_frames_decoded=%u",
                            channel_id,
                            end_frame.frame_id,
                            session->graphics_frames_decoded);
            status = rdp_session_send_graphics_frame_ack(session, end_frame.frame_id);
            if (status != LIBRDP_STATUS_OK)
                break;
        }
        offset += header.pdu_length;
    }

    rdp_buffer_free(&decoded);
    return status;
}

static librdp_status rdp_session_join_mcs_channel(librdp_session* session,
                                                  uint16_t channel_id,
                                                  const char* name,
                                                  rdp_buffer* request,
                                                  rdp_buffer* reply)
{
    const uint8_t* pdu = NULL;
    size_t pdu_len = 0;
    rdp_mcs_channel_join_confirm confirm;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !request || !reply)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_free(request);
    rdp_buffer_init(request);
    status = rdp_mcs_write_channel_join_request(request, session->mcs_user_id, channel_id);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "mcs.channel_join.request",
                    "channel_id=%u name=%s",
                    channel_id,
                    name ? name : "");
    status = rdp_session_write_mcs_pdu(session, request, "mcs.channel_join.request", 1);
    if (status != LIBRDP_STATUS_OK)
        return status;

    rdp_buffer_free(reply);
    rdp_buffer_init(reply);
    status = rdp_session_read_mcs_pdu(session, reply, &pdu, &pdu_len, "mcs.channel_join.confirm");
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_mcs_parse_channel_join_confirm(pdu, pdu_len, &confirm);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (confirm.result != 0 || confirm.initiator != session->mcs_user_id || confirm.channel_id != channel_id)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "mcs.channel_join.failed",
                        "result=%u initiator=%u channel_id=%u",
                        confirm.result,
                        confirm.initiator,
                        confirm.channel_id);
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    }
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "mcs.channel_join.confirm",
                    "channel_id=%u name=%s",
                    confirm.channel_id,
                    name ? name : "");
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_send_activation_finalization(librdp_session* session, uint32_t share_id)
{
    rdp_buffer sync;
    rdp_buffer cooperate;
    rdp_buffer request;
    rdp_buffer persistent_keys;
    rdp_buffer font_list;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&sync);
    rdp_buffer_init(&cooperate);
    rdp_buffer_init(&request);
    rdp_buffer_init(&persistent_keys);
    rdp_buffer_init(&font_list);

    status = rdp_slowpath_write_client_synchronize(&sync, share_id, session->mcs_user_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &sync, "rdp.activation.client_synchronize");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_synchronize", "share_id=%u", share_id);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_client_control(&cooperate, share_id, session->mcs_user_id, 4);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &cooperate, "rdp.activation.client_control_cooperate");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_control_cooperate", "share_id=%u", share_id);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_client_control(&request, share_id, session->mcs_user_id, 1);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &request, "rdp.activation.client_control_request");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_control_request", "share_id=%u", share_id);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_client_persistent_key_list(&persistent_keys, share_id, session->mcs_user_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &persistent_keys, "rdp.activation.client_persistent_key_list");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_persistent_key_list", "share_id=%u entries=0", share_id);

    if (status == LIBRDP_STATUS_OK)
        status = rdp_slowpath_write_client_font_list(&font_list, share_id, session->mcs_user_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &font_list, "rdp.activation.client_font_list");
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.client_font_list", "share_id=%u", share_id);

    rdp_buffer_free(&font_list);
    rdp_buffer_free(&persistent_keys);
    rdp_buffer_free(&request);
    rdp_buffer_free(&cooperate);
    rdp_buffer_free(&sync);
    return status;
}

static librdp_status rdp_session_send_active_output_request(librdp_session* session)
{
    rdp_buffer suppress;
    librdp_status status = LIBRDP_STATUS_OK;
    uint32_t width = 0;
    uint32_t height = 0;

    if (!session || !session->surface || session->share_id == 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    width = librdp_surface_width(session->surface);
    height = librdp_surface_height(session->surface);
    if (width == 0 || height == 0 || width > 0xffffu || height > 0xffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&suppress);
    status = rdp_slowpath_write_client_suppress_output(&suppress,
                                                       session->share_id,
                                                       session->mcs_user_id,
                                                       1,
                                                       0,
                                                       0,
                                                       (uint16_t)width,
                                                       (uint16_t)height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &suppress, "rdp.activation.client_suppress_output");
    rdp_buffer_free(&suppress);
    if (status != LIBRDP_STATUS_OK)
        return status;

    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "rdp.activation.client_suppress_output",
                    "share_id=%u width=%u height=%u",
                    session->share_id,
                    width,
                    height);
    return librdp_session_refresh(session, 0, 0, width, height);
}

static librdp_status rdp_session_trace_slowpath_data_pdu(librdp_session* session, const rdp_slowpath_data_pdu* data_pdu)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!data_pdu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    if (data_pdu->pdu_type2 == RDP_SLOWPATH_DATA_PDU_FONT_MAP)
    {
        rdp_slowpath_font_map font_map;

        status = rdp_slowpath_parse_font_map(data_pdu->payload, data_pdu->payload_len, &font_map);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "rdp.activation.font_map",
                            "entries=%u total_entries=%u flags=%u entry_size=%u",
                            font_map.number_entries,
                            font_map.total_entries,
                            font_map.map_flags,
                            font_map.entry_size);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_send_active_output_request(session);
    }
    else if (data_pdu->pdu_type2 == RDP_SLOWPATH_DATA_PDU_SET_ERROR_INFO)
    {
        uint32_t error_info = 0;

        status = rdp_slowpath_parse_set_error_info(data_pdu->payload, data_pdu->payload_len, &error_info);
        if (status == LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.set_error_info", "error_info=%u", error_info);
            if (error_info != 0)
                status = LIBRDP_STATUS_PROTOCOL_ERROR;
        }
    }
    else if (data_pdu->pdu_type2 == RDP_SLOWPATH_DATA_PDU_SAVE_SESSION_INFO)
    {
        rdp_slowpath_save_session_info info;

        status = rdp_slowpath_parse_save_session_info(data_pdu->payload, data_pdu->payload_len, &info);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "rdp.save_session_info",
                            "info_type=%u data_len=%u",
                            info.info_type,
                            (unsigned)info.data_len);
    }

    return status;
}

static librdp_status rdp_session_handle_mouse_cursor_message(librdp_session* session,
                                                             uint32_t channel_id,
                                                             const uint8_t* data,
                                                             size_t data_len)
{
    rdp_mouse_cursor_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_mouse_cursor_parse_header(data, data_len, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;

    if (header.pdu_type == RDP_MOUSE_CURSOR_PDU_SC_CAPS_CONFIRM)
    {
        rdp_mouse_cursor_capset capset;

        status = rdp_mouse_cursor_parse_caps_confirm(data, data_len, &capset);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session->mouse_cursor_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.mouse_cursor.caps_confirm",
                        "dvc_channel_id=%u version=%u size=%u",
                        channel_id,
                        capset.version,
                        capset.size);
        return LIBRDP_STATUS_OK;
    }

    if (header.pdu_type == RDP_MOUSE_CURSOR_PDU_SC_MOUSEPTR_UPDATE)
    {
        rdp_pointer_update update;

        status = rdp_mouse_cursor_parse_update(data, data_len, &update);
        if (status == LIBRDP_STATUS_UNSUPPORTED)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.mouse_cursor.update.unsupported",
                            "dvc_channel_id=%u update_type=%u payload_len=%u",
                            channel_id,
                            header.update_type,
                            (unsigned)data_len);
            return LIBRDP_STATUS_OK;
        }
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.mouse_cursor.update",
                        "dvc_channel_id=%u update_type=%u kind=%u cache_index=%u width=%u height=%u",
                        channel_id,
                        header.update_type,
                        update.kind,
                        update.cache_index,
                        update.width,
                        update.height);
        status = rdp_session_pointer_apply_update(session, &update);
        if (status == LIBRDP_STATUS_UNSUPPORTED)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.mouse_cursor.shape.unsupported",
                            "dvc_channel_id=%u update_type=%u xor_bpp=%u width=%u height=%u",
                            channel_id,
                            header.update_type,
                            update.xor_bpp,
                            update.width,
                            update.height);
            return LIBRDP_STATUS_OK;
        }
        return status;
    }

    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.mouse_cursor.pdu.unsupported",
                    "dvc_channel_id=%u pdu_type=%u update_type=%u payload_len=%u",
                    channel_id,
                    header.pdu_type,
                    header.update_type,
                    (unsigned)data_len);
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_handle_dynamic_channel_message(librdp_session* session,
                                                                rdp_session_dynamic_channel* entry,
                                                                uint32_t channel_id,
                                                                uint8_t channel_id_bytes,
                                                                const uint8_t* data,
                                                                size_t data_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !entry || (!data && data_len > 0))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_trace_event(RDP_TRACE_CLIENT,
                    "client.drdynvc.data",
                    "dvc_channel_id=%u name=%s payload_len=%u",
                    channel_id,
                    entry->name,
                    (unsigned)data_len);
    if (strcmp(entry->name, "ECHO") == 0)
    {
        status = rdp_session_send_dynamic_channel_data(session,
                                                       channel_id,
                                                       channel_id_bytes,
                                                       data,
                                                       data_len,
                                                       "client.drdynvc.echo");
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.drdynvc.echo",
                        "dvc_channel_id=%u payload_len=%u",
                        channel_id,
                        (unsigned)data_len);
    }
    else if (strcmp(entry->name, RDP_SESSION_DISPLAY_CONTROL_NAME) == 0)
    {
        rdp_display_control_caps caps;

        status = rdp_display_control_parse_caps(data, data_len, &caps);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session->display_control_caps = caps;
        session->display_control_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.display_control.caps",
                        "dvc_channel_id=%u max_monitors=%u area_a=%u area_b=%u",
                        channel_id,
                        caps.max_num_monitors,
                        caps.max_monitor_area_factor_a,
                        caps.max_monitor_area_factor_b);
        status = rdp_session_request_display_control_layout(
            session,
            session->requested_desktop_width != 0 ? session->requested_desktop_width :
                                                    librdp_surface_width(session->surface),
            session->requested_desktop_height != 0 ? session->requested_desktop_height :
                                                     librdp_surface_height(session->surface));
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    else if (strcmp(entry->name, RDP_SESSION_CORE_INPUT_NAME) == 0)
    {
        rdp_core_input_init_response response;

        status = rdp_core_input_parse_init_response(data, data_len, &response);
        if (status != LIBRDP_STATUS_OK)
            return status;
        session->core_input_ready = 1;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.core_input.ready",
                        "dvc_channel_id=%u selected_version=%u max_version=%u",
                        channel_id,
                        response.selected_protocol_version,
                        response.protocol_version_max);
    }
    else if (strcmp(entry->name, RDP_SESSION_MOUSE_CURSOR_NAME) == 0)
    {
        status = rdp_session_handle_mouse_cursor_message(session, channel_id, data, data_len);
    }
    else if (strcmp(entry->name, RDP_SESSION_GRAPHICS_PIPELINE_NAME) == 0)
    {
        status = rdp_session_handle_graphics_message(session, channel_id, data, data_len);
    }
    return status;
}

static librdp_status rdp_session_handle_dynamic_channel(librdp_session* session,
                                                        const rdp_virtual_channel_packet* channel_packet)
{
    rdp_dynamic_channel_header header;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !channel_packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_dynamic_channel_parse_header(channel_packet->payload, channel_packet->payload_len, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;

    if (header.command == RDP_DYNAMIC_CHANNEL_CMD_CAPABILITIES)
    {
        rdp_dynamic_channel_capabilities capabilities;
        rdp_buffer response;

        rdp_buffer_init(&response);
        status = rdp_dynamic_channel_parse_capabilities(channel_packet->payload,
                                                        channel_packet->payload_len,
                                                        &capabilities);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_dynamic_channel_write_capabilities_response(&response, 1);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_write_channel_pdu(session,
                                                   session->dynamic_channel_id,
                                                   &response,
                                                   "client.drdynvc.capabilities");
        rdp_buffer_free(&response);
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.drdynvc.capabilities",
                        "server_version=%u client_version=1",
                        capabilities.version);
    }
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_CREATE)
    {
        rdp_dynamic_channel_create_request request;
        rdp_buffer response;
        size_t trace_name_len = 0;
        int name_len = 0;

        rdp_buffer_init(&response);
        status = rdp_dynamic_channel_parse_create_request(channel_packet->payload,
                                                          channel_packet->payload_len,
                                                          &request);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_dynamic_channel_write_create_response(&response,
                                                               request.channel_id,
                                                               request.channel_id_bytes,
                                                               RDP_DYNAMIC_CHANNEL_STATUS_OK);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_dynamic_channel_add(session, &request);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_write_channel_pdu(session,
                                                   session->dynamic_channel_id,
                                                   &response,
                                                   "client.drdynvc.create");
        rdp_buffer_free(&response);
        if (status != LIBRDP_STATUS_OK)
            return status;
        trace_name_len = request.name_len > 120u ? 120u : request.name_len;
        name_len = (int)trace_name_len;
        if (request.name_len == sizeof(RDP_SESSION_DISPLAY_CONTROL_NAME) - 1u &&
            memcmp(request.name, RDP_SESSION_DISPLAY_CONTROL_NAME, request.name_len) == 0)
        {
            session->display_control_channel_id = request.channel_id;
            session->display_control_channel_id_bytes = request.channel_id_bytes;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.display_control.channel",
                            "dvc_channel_id=%u",
                            request.channel_id);
        }
        else if (request.name_len == sizeof(RDP_SESSION_CORE_INPUT_NAME) - 1u &&
                 memcmp(request.name, RDP_SESSION_CORE_INPUT_NAME, request.name_len) == 0)
        {
            session->core_input_channel_id = request.channel_id;
            session->core_input_channel_id_bytes = request.channel_id_bytes;
            session->core_input_ready = 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.core_input.channel",
                            "dvc_channel_id=%u",
                            request.channel_id);
            status = rdp_session_send_core_input_init(session);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else if (request.name_len == sizeof(RDP_SESSION_MOUSE_CURSOR_NAME) - 1u &&
                 memcmp(request.name, RDP_SESSION_MOUSE_CURSOR_NAME, request.name_len) == 0)
        {
            session->mouse_cursor_channel_id = request.channel_id;
            session->mouse_cursor_channel_id_bytes = request.channel_id_bytes;
            session->mouse_cursor_ready = 0;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.mouse_cursor.channel",
                            "dvc_channel_id=%u",
                            request.channel_id);
            status = rdp_session_send_mouse_cursor_caps(session);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        else if (request.name_len == sizeof(RDP_SESSION_GRAPHICS_PIPELINE_NAME) - 1u &&
                 memcmp(request.name, RDP_SESSION_GRAPHICS_PIPELINE_NAME, request.name_len) == 0)
        {
            session->graphics_channel_id = request.channel_id;
            session->graphics_channel_id_bytes = request.channel_id_bytes;
            session->graphics_ready = 0;
            session->graphics_selected_version = 0;
            session->graphics_selected_flags = 0;
            session->graphics_frames_decoded = 0;
            rdp_graphics_decompressor_reset(&session->graphics_decompressor);
            rdp_clearcodec_context_reset(&session->clearcodec);
            rdp_session_graphics_surfaces_clear(session);
            rdp_session_graphics_cache_clear(session);
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.graphics.channel",
                            "dvc_channel_id=%u",
                            request.channel_id);
            status = rdp_session_send_graphics_caps(session);
            if (status != LIBRDP_STATUS_OK)
                return status;
        }
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.drdynvc.create",
                        "channel_id=%u name=%.*s status=0",
                        request.channel_id,
                        name_len,
                        request.name);
    }
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_DATA_FIRST)
    {
        rdp_dynamic_channel_data_first_pdu first_pdu;
        rdp_session_dynamic_channel* entry = NULL;

        status = rdp_dynamic_channel_parse_data_first(channel_packet->payload,
                                                      channel_packet->payload_len,
                                                      &first_pdu);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (first_pdu.total_length == 0 || first_pdu.total_length > RDP_SESSION_MAX_DYNAMIC_MESSAGE)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        entry = rdp_session_dynamic_channel_find(session, first_pdu.channel_id);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.drdynvc.fragment.start",
                        "dvc_channel_id=%u name=%s total_len=%u payload_len=%u",
                        first_pdu.channel_id,
                        entry ? entry->name : "",
                        first_pdu.total_length,
                        (unsigned)first_pdu.data_len);
        if (!entry)
            return LIBRDP_STATUS_OK;
        rdp_buffer_free(&entry->fragment);
        rdp_buffer_init(&entry->fragment);
        status = rdp_buffer_reserve(&entry->fragment, first_pdu.total_length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_buffer_append(&entry->fragment, first_pdu.data, first_pdu.data_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
        entry->fragment_expected = first_pdu.total_length;
        entry->fragmenting = entry->fragment.length < entry->fragment_expected;
        if (!entry->fragmenting)
        {
            status = rdp_session_handle_dynamic_channel_message(session,
                                                                entry,
                                                                first_pdu.channel_id,
                                                                first_pdu.channel_id_bytes,
                                                                entry->fragment.data,
                                                                entry->fragment.length);
            rdp_buffer_free(&entry->fragment);
            entry->fragment_expected = 0;
        }
    }
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_DATA)
    {
        rdp_dynamic_channel_data_pdu data_pdu;
        rdp_session_dynamic_channel* entry = NULL;

        status = rdp_dynamic_channel_parse_data(channel_packet->payload, channel_packet->payload_len, &data_pdu);
        if (status != LIBRDP_STATUS_OK)
            return status;

        entry = rdp_session_dynamic_channel_find(session, data_pdu.channel_id);
        if (!entry)
        {
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.drdynvc.data",
                            "dvc_channel_id=%u name= payload_len=%u",
                            data_pdu.channel_id,
                            (unsigned)data_pdu.data_len);
            return LIBRDP_STATUS_OK;
        }
        if (entry->fragmenting)
        {
            if (data_pdu.data_len > (size_t)entry->fragment_expected - entry->fragment.length)
                return LIBRDP_STATUS_PROTOCOL_ERROR;
            status = rdp_buffer_append(&entry->fragment, data_pdu.data, data_pdu.data_len);
            if (status != LIBRDP_STATUS_OK)
                return status;
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.drdynvc.fragment.data",
                            "dvc_channel_id=%u name=%s total_len=%u received=%u payload_len=%u",
                            data_pdu.channel_id,
                            entry->name,
                            entry->fragment_expected,
                            (unsigned)entry->fragment.length,
                            (unsigned)data_pdu.data_len);
            if (entry->fragment.length < entry->fragment_expected)
                return LIBRDP_STATUS_OK;
            entry->fragmenting = 0;
            status = rdp_session_handle_dynamic_channel_message(session,
                                                                entry,
                                                                data_pdu.channel_id,
                                                                data_pdu.channel_id_bytes,
                                                                entry->fragment.data,
                                                                entry->fragment.length);
            rdp_buffer_free(&entry->fragment);
            entry->fragment_expected = 0;
            return status;
        }
        status = rdp_session_handle_dynamic_channel_message(session,
                                                            entry,
                                                            data_pdu.channel_id,
                                                            data_pdu.channel_id_bytes,
                                                            data_pdu.data,
                                                            data_pdu.data_len);
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    else if (header.command == RDP_DYNAMIC_CHANNEL_CMD_CLOSE)
    {
        rdp_dynamic_channel_close_pdu close_pdu;
        rdp_session_dynamic_channel* entry = NULL;

        status = rdp_dynamic_channel_parse_close(channel_packet->payload, channel_packet->payload_len, &close_pdu);
        if (status != LIBRDP_STATUS_OK)
            return status;
        entry = rdp_session_dynamic_channel_find(session, close_pdu.channel_id);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.drdynvc.close",
                        "dvc_channel_id=%u name=%s",
                        close_pdu.channel_id,
                        entry ? entry->name : "");
        if (entry)
        {
            if (entry->channel_id == session->display_control_channel_id)
            {
                session->display_control_channel_id = 0;
                session->display_control_channel_id_bytes = 0;
                session->display_control_ready = 0;
                session->sent_desktop_width = 0;
                session->sent_desktop_height = 0;
                memset(&session->display_control_caps, 0, sizeof(session->display_control_caps));
            }
            if (entry->channel_id == session->core_input_channel_id)
            {
                session->core_input_channel_id = 0;
                session->core_input_channel_id_bytes = 0;
                session->core_input_ready = 0;
            }
            if (entry->channel_id == session->mouse_cursor_channel_id)
            {
                session->mouse_cursor_channel_id = 0;
                session->mouse_cursor_channel_id_bytes = 0;
                session->mouse_cursor_ready = 0;
                rdp_session_pointer_emit_default(session);
            }
            if (entry->channel_id == session->graphics_channel_id)
            {
                session->graphics_channel_id = 0;
                session->graphics_channel_id_bytes = 0;
                session->graphics_ready = 0;
                session->graphics_selected_version = 0;
                session->graphics_selected_flags = 0;
                session->graphics_frames_decoded = 0;
                rdp_graphics_decompressor_reset(&session->graphics_decompressor);
                rdp_clearcodec_context_reset(&session->clearcodec);
                rdp_session_graphics_surfaces_clear(session);
                rdp_session_graphics_cache_clear(session);
            }
            rdp_buffer_free(&entry->fragment);
            entry->fragment_expected = 0;
            entry->fragmenting = 0;
            entry->active = 0;
        }
    }
    else
    {
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.drdynvc.data",
                        "command=%u payload_len=%u",
                        header.command,
                        (unsigned)channel_packet->payload_len);
    }

    return status;
}

static librdp_status rdp_session_read_mcs_pdu(librdp_session* session,
                                              rdp_buffer* packet,
                                              const uint8_t** pdu,
                                              size_t* pdu_len,
                                              const char* event)
{
    rdp_tpkt parsed;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !packet || !pdu || !pdu_len || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_transport_read_tpkt(&session->transport, packet);
    if (status != LIBRDP_STATUS_OK)
        return status;
    rdp_trace_hexdump(event, packet->data, packet->length);
    status = rdp_tpkt_parse(packet->data, packet->length, &parsed);
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_x224_parse_data(parsed.payload, parsed.payload_len, pdu, pdu_len);
}

static librdp_status rdp_session_read_fastpath_packet(librdp_session* session, rdp_buffer* packet)
{
    uint8_t header[3];
    uint16_t total = 0;
    size_t header_len = 2;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_free(packet);
    rdp_buffer_init(packet);

    status = rdp_transport_read_exact(&session->transport, header, 2);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if ((header[1] & 0x80u) != 0)
    {
        status = rdp_transport_read_exact(&session->transport, header + 2, 1);
        if (status != LIBRDP_STATUS_OK)
            return status;
        total = (uint16_t)(((uint16_t)(header[1] & 0x7fu) << 8) | header[2]);
        header_len = 3;
    }
    else
    {
        total = header[1];
    }
    if (total < header_len)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    status = rdp_buffer_append(packet, header, header_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_reserve(packet, total);
    if (status != LIBRDP_STATUS_OK)
        return status;
    packet->length = total;
    status = rdp_transport_read_exact(&session->transport, packet->data + header_len, (size_t)total - header_len);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_hexdump("rdp.fastpath.pdu", packet->data, packet->length);
    return status;
}

static librdp_status rdp_session_write_fastpath_header(rdp_buffer* buffer,
                                                       uint8_t first,
                                                       uint16_t length,
                                                       size_t header_len)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!buffer || (header_len != 2u && header_len != 3u) || length < header_len)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_buffer_append_u8(buffer, (uint8_t)(first & 0x3fu));
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (header_len == 2u)
    {
        if (length > 0x7fu)
            return LIBRDP_STATUS_INVALID_ARGUMENT;
        return rdp_buffer_append_u8(buffer, (uint8_t)length);
    }

    status = rdp_buffer_append_u8(buffer, (uint8_t)(0x80u | ((length >> 8) & 0x7fu)));
    if (status != LIBRDP_STATUS_OK)
        return status;
    return rdp_buffer_append_u8(buffer, (uint8_t)(length & 0xffu));
}

static librdp_status rdp_session_unwrap_fastpath_packet(librdp_session* session,
                                                        const rdp_buffer* packet,
                                                        rdp_buffer* decoded,
                                                        int* used_decoded)
{
    rdp_fastpath_header header;
    const uint8_t* signature = NULL;
    uint8_t* encrypted = NULL;
    uint16_t decoded_len = 0;
    size_t encrypted_len = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !packet || !decoded || !used_decoded)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    *used_decoded = 0;
    status = rdp_fastpath_parse_header(packet->data, packet->length, &header);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if ((header.security_flags & RDP_FASTPATH_OUTPUT_ENCRYPTED) == 0)
    {
        if (header.security_flags != 0)
            return LIBRDP_STATUS_UNSUPPORTED;
        return LIBRDP_STATUS_OK;
    }
    if (!session->standard_security_active || header.length < header.header_length + 8u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;

    decoded_len = (uint16_t)(header.length - 8u);
    signature = packet->data + header.header_length;
    encrypted = packet->data + header.header_length + 8u;
    encrypted_len = header.length - header.header_length - 8u;

    status = rdp_session_write_fastpath_header(decoded, packet->data[0], decoded_len, header.header_length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(decoded, encrypted, encrypted_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_decrypt_payload(&session->standard_security,
                                              decoded->data + header.header_length,
                                              encrypted_len);
    if (status == LIBRDP_STATUS_OK &&
        (header.security_flags & RDP_FASTPATH_OUTPUT_SECURE_CHECKSUM) == 0)
    {
        uint8_t expected[8];
        status = rdp_security_mac_signature(&session->standard_security,
                                            decoded->data + header.header_length,
                                            encrypted_len,
                                            expected);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (memcmp(signature, expected, sizeof(expected)) != 0)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "rdp.fastpath.signature.mismatch",
                            "payload_len=%u",
                            (unsigned)encrypted_len);
    }
    if (status == LIBRDP_STATUS_OK)
        *used_decoded = 1;
    return status;
}

static librdp_status rdp_session_read_credssp_ts_request(librdp_session* session, rdp_buffer* packet, int timeout_ms)
{
    uint8_t header[6];
    uint8_t first_len = 0;
    size_t header_len = 0;
    size_t content_len = 0;
    size_t i = 0;
    short revents = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !packet || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_free(packet);
    rdp_buffer_init(packet);

    status = rdp_transport_wait(&session->transport, timeout_ms, POLLIN, &revents);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if ((revents & POLLIN) == 0)
        return LIBRDP_STATUS_TIMEOUT;

    status = rdp_transport_read_exact(&session->transport, header, 2);
    if (status != LIBRDP_STATUS_OK)
        return status;
    if (header[0] != 0x30)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    first_len = header[1];
    header_len = 2;
    if ((first_len & 0x80u) == 0)
    {
        content_len = first_len;
    }
    else
    {
        uint8_t count = (uint8_t)(first_len & 0x7fu);
        if (count == 0 || count > 4)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        status = rdp_transport_read_exact(&session->transport, header + 2, count);
        if (status != LIBRDP_STATUS_OK)
            return status;
        header_len += count;
        for (i = 0; i < count; i++)
            content_len = (content_len << 8) | header[2u + i];
    }
    if (content_len == 0 || content_len > 1024u * 1024u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    status = rdp_buffer_append(packet, header, header_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    status = rdp_buffer_reserve(packet, header_len + content_len);
    if (status != LIBRDP_STATUS_OK)
        return status;
    packet->length = header_len + content_len;
    return rdp_transport_read_exact(&session->transport, packet->data + header_len, content_len);
}

static librdp_status rdp_session_apply_bitmap_update(librdp_session* session, const rdp_bitmap_update* update)
{
    uint16_t i = 0;

    if (!session || !update)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    for (i = 0; i < update->count; i++)
    {
        const rdp_bitmap_rect* rect = &update->rects[i];
        size_t stride = 0;
        rdp_buffer pixels;
        librdp_status status = LIBRDP_STATUS_OK;

        rdp_buffer_init(&pixels);
        status = rdp_bitmap_decode_rect_bgra32(rect, &pixels, &stride);
        if (status == LIBRDP_STATUS_OK)
            status = librdp_surface_blit_bgra32(session->surface,
                                                rect->dest_left,
                                                rect->dest_top,
                                                rect->width,
                                                rect->height,
                                                pixels.data,
                                                stride);
        rdp_buffer_free(&pixels);
        if (status != LIBRDP_STATUS_OK)
            return status;
        rdp_session_emit_surface_invalidated(session, rect->dest_left, rect->dest_top, rect->width, rect->height);
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.active.framebuffer.blit",
                        "x=%u y=%u width=%u height=%u",
                        rect->dest_left,
                        rect->dest_top,
                        rect->width,
                        rect->height);
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status rdp_session_process_fastpath_packet(librdp_session* session, const rdp_buffer* packet)
{
    rdp_buffer decoded;
    const rdp_buffer* parse_packet = packet;
    rdp_fastpath_update_list updates;
    uint16_t i = 0;
    int used_decoded = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || !packet)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_buffer_init(&decoded);
    status = rdp_session_unwrap_fastpath_packet(session, packet, &decoded, &used_decoded);
    if (status == LIBRDP_STATUS_OK && used_decoded)
        parse_packet = &decoded;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_fastpath_parse_updates(parse_packet->data, parse_packet->length, &updates);
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&decoded);
        return status;
    }

    for (i = 0; i < updates.count; i++)
    {
        const rdp_fastpath_update* update = &updates.updates[i];

        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "rdp.fastpath.update",
                        "code=%u fragmentation=%u compression=%u payload_len=%u",
                        update->update_code,
                        update->fragmentation,
                        update->compression,
                        (unsigned)update->data_len);
        if (update->update_code == RDP_FASTPATH_UPDATE_BITMAP)
        {
            rdp_bitmap_update bitmap;

            if (update->fragmentation != RDP_FASTPATH_FRAGMENT_SINGLE || update->compression != 0)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.fastpath.update.unsupported",
                                "code=%u fragmentation=%u compression=%u payload_len=%u",
                                update->update_code,
                                update->fragmentation,
                                update->compression,
                                (unsigned)update->data_len);
            }
            else
            {
                status = rdp_bitmap_parse_fastpath_update(update->data, update->data_len, &bitmap);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_apply_bitmap_update(session, &bitmap);
                if (status != LIBRDP_STATUS_OK)
                    goto out;
                rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.fastpath.bitmap_update", "rectangles=%u", bitmap.count);
            }
        }
        else if (update->update_code == RDP_FASTPATH_UPDATE_POINTER_NULL ||
                 update->update_code == RDP_FASTPATH_UPDATE_POINTER_DEFAULT ||
                 update->update_code == RDP_FASTPATH_UPDATE_POINTER_POSITION ||
                 update->update_code == RDP_FASTPATH_UPDATE_POINTER_COLOR ||
                 update->update_code == RDP_FASTPATH_UPDATE_POINTER_CACHED ||
                 update->update_code == RDP_FASTPATH_UPDATE_POINTER_NEW ||
                 update->update_code == RDP_FASTPATH_UPDATE_POINTER_LARGE)
        {
            rdp_pointer_update pointer;

            if (update->fragmentation != RDP_FASTPATH_FRAGMENT_SINGLE || update->compression != 0)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.fastpath.pointer.unsupported",
                                "code=%u fragmentation=%u compression=%u payload_len=%u",
                                update->update_code,
                                update->fragmentation,
                                update->compression,
                                (unsigned)update->data_len);
            }
            else
            {
                status = rdp_pointer_parse_fastpath(update->update_code, update->data, update->data_len, &pointer);
                if (status == LIBRDP_STATUS_OK)
                    status = rdp_session_pointer_apply_update(session, &pointer);
                if (status != LIBRDP_STATUS_OK)
                    goto out;
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.fastpath.pointer",
                                "code=%u kind=%u cache_index=%u width=%u height=%u",
                                update->update_code,
                                pointer.kind,
                                pointer.cache_index,
                                pointer.width,
                                pointer.height);
            }
        }
    }

out:
    rdp_buffer_free(&decoded);
    return status;
}

librdp_session* librdp_session_new(const librdp_settings* settings)
{
    librdp_session* session = NULL;

    if (!settings)
        return NULL;

    session = (librdp_session*)calloc(1, sizeof(*session));
    if (!session)
        return NULL;

    session->settings = librdp_settings_clone(settings);
    if (!session->settings)
    {
        free(session);
        return NULL;
    }

    session->surface = librdp_surface_new(librdp_settings_width(session->settings),
                                          librdp_settings_height(session->settings),
                                          LIBRDP_PIXEL_FORMAT_BGRA32);
    if (!session->surface)
    {
        librdp_settings_free(session->settings);
        free(session);
        return NULL;
    }

    session->state = LIBRDP_SESSION_IDLE;
    session->requested_desktop_width = librdp_settings_width(session->settings);
    session->requested_desktop_height = librdp_settings_height(session->settings);
    rdp_transport_init(&session->transport);
    rdp_graphics_decompressor_init(&session->graphics_decompressor);
    rdp_clearcodec_context_init(&session->clearcodec);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.session.new", "width=%u height=%u",
                    librdp_settings_width(session->settings),
                    librdp_settings_height(session->settings));
    return session;
}

void librdp_session_free(librdp_session* session)
{
    if (!session)
        return;
    (void)librdp_session_disconnect(session);
    rdp_session_dynamic_channels_clear(session);
    rdp_session_graphics_surfaces_clear(session);
    rdp_session_graphics_cache_clear(session);
    rdp_session_pointer_cache_clear(session);
    rdp_clearcodec_context_free(&session->clearcodec);
    rdp_graphics_decompressor_free(&session->graphics_decompressor);
    rdp_security_standard_clear(&session->standard_security);
    rdp_transport_close(&session->transport);
    librdp_surface_free(session->surface);
    librdp_settings_free(session->settings);
    free(session);
}

void librdp_session_set_event_callback(librdp_session* session, librdp_event_callback callback, void* user_data)
{
    if (!session)
        return;
    session->callback = callback;
    session->callback_data = user_data;
}

librdp_status librdp_session_connect(librdp_session* session)
{
    rdp_buffer x224;
    rdp_buffer gcc_blocks;
    rdp_buffer gcc_request;
    rdp_buffer mcs;
    rdp_buffer security_payload;
    rdp_buffer security_data;
    rdp_buffer server_random;
    rdp_buffer server_certificate;
    rdp_buffer request;
    rdp_buffer reply;
    rdp_tpkt packet;
    rdp_x224_connection_confirm confirm;
    rdp_mcs_connect_response mcs_response;
    rdp_gcc_conference_response gcc_response;
    rdp_gcc_server_data server_data;
    rdp_mcs_attach_user_confirm attach_confirm;
    rdp_credssp_state credssp_state = RDP_CREDSSP_DISABLED;
    const uint8_t* mcs_pdu = NULL;
    size_t mcs_pdu_len = 0;
    uint32_t protocols = 0;
    uint32_t selected_protocol = 0;
    uint32_t server_encryption_method = 0;
    uint32_t server_encryption_level = 0;
    int standard_security_ready = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_IDLE && session->state != LIBRDP_SESSION_CLOSED &&
        session->state != LIBRDP_SESSION_FAILED)
        return LIBRDP_STATUS_STATE;
    if (!librdp_settings_target(session->settings))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    rdp_trace_event(RDP_TRACE_CLIENT, "client.connect.start", "target=%s port=%u width=%u height=%u",
                    librdp_settings_target(session->settings),
                    (unsigned)librdp_settings_port(session->settings),
                    librdp_settings_width(session->settings),
                    librdp_settings_height(session->settings));

    rdp_buffer_init(&x224);
    rdp_buffer_init(&gcc_blocks);
    rdp_buffer_init(&gcc_request);
    rdp_buffer_init(&mcs);
    rdp_buffer_init(&security_payload);
    rdp_buffer_init(&security_data);
    rdp_buffer_init(&server_random);
    rdp_buffer_init(&server_certificate);
    rdp_buffer_init(&request);
    rdp_buffer_init(&reply);

    rdp_session_set_state(session, LIBRDP_SESSION_CONNECTING);
    rdp_security_standard_clear(&session->standard_security);
    session->standard_security_active = 0;
    session->share_id = 0;
    session->dynamic_channel_id = 0;
    session->core_input_channel_id = 0;
    session->core_input_channel_id_bytes = 0;
    session->core_input_ready = 0;
    session->display_control_channel_id = 0;
    session->display_control_channel_id_bytes = 0;
    session->display_control_ready = 0;
    session->sent_desktop_width = 0;
    session->sent_desktop_height = 0;
    memset(&session->display_control_caps, 0, sizeof(session->display_control_caps));
    session->graphics_channel_id = 0;
    session->graphics_channel_id_bytes = 0;
    session->graphics_ready = 0;
    session->graphics_selected_version = 0;
    session->graphics_selected_flags = 0;
    session->graphics_frames_decoded = 0;
    session->mouse_cursor_channel_id = 0;
    session->mouse_cursor_channel_id_bytes = 0;
    session->mouse_cursor_ready = 0;
    rdp_graphics_decompressor_reset(&session->graphics_decompressor);
    rdp_clearcodec_context_reset(&session->clearcodec);
    rdp_session_graphics_surfaces_clear(session);
    rdp_session_graphics_cache_clear(session);
    rdp_session_pointer_cache_clear(session);
    rdp_session_dynamic_channels_clear(session);

    status = rdp_transport_connect(&session->transport,
                                   librdp_settings_target(session->settings),
                                   librdp_settings_port(session->settings),
                                   5000);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    protocols = rdp_security_protocol_mask(librdp_settings_security_mode(session->settings));
    rdp_trace_event(RDP_TRACE_PROTOCOL, "x224.negotiation.start", "protocols=%u", protocols);
    status = rdp_x224_build_connection_request(&x224, librdp_settings_username(session->settings), protocols);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    status = rdp_tpkt_write(&request, x224.data, x224.length);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_hexdump("x224.negotiation.request", request.data, request.length);
    status = rdp_transport_write_all(&session->transport, request.data, request.length);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    status = rdp_transport_read_tpkt(&session->transport, &reply);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_hexdump("x224.negotiation.response", reply.data, reply.length);
    status = rdp_tpkt_parse(reply.data, reply.length, &packet);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    status = rdp_x224_parse_connection_confirm(packet.payload, packet.payload_len, &confirm);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    if (confirm.negotiation.present && confirm.negotiation.failure)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL, "x224.negotiation.failed", "code=%u", confirm.negotiation.failure_code);
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto fail;
    }
    if (confirm.negotiation.present && !rdp_security_protocol_supported(confirm.negotiation.selected_protocol))
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL, "x224.negotiation.unsupported", "selected_protocol=%u",
                        confirm.negotiation.selected_protocol);
        status = LIBRDP_STATUS_UNSUPPORTED;
        goto fail;
    }

    rdp_trace_event(RDP_TRACE_PROTOCOL, "x224.negotiation.done", "selected_protocol=%u",
                    confirm.negotiation.present ? confirm.negotiation.selected_protocol : 0);
    selected_protocol = confirm.negotiation.present ? confirm.negotiation.selected_protocol : 0;
    if (selected_protocol == RDP_X224_PROTOCOL_TLS || selected_protocol == RDP_X224_PROTOCOL_NLA)
    {
        status = rdp_transport_start_tls(&session->transport, librdp_settings_target(session->settings));
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        rdp_trace_event(RDP_TRACE_PROTOCOL, "transport.tls.ready", "selected_protocol=%u", selected_protocol);
    }
    if (selected_protocol == RDP_X224_PROTOCOL_NLA)
    {
        rdp_buffer credssp_request;
        rdp_buffer credssp_reply;
        rdp_buffer ntlm_negotiate;
        rdp_buffer spnego_negotiate;
        rdp_buffer ntlm_authenticate;
        rdp_buffer spnego_authenticate;
        rdp_buffer tls_public_key;
        rdp_buffer pub_key_auth;
        rdp_buffer auth_info;
        rdp_credssp_ts_request ts_response;
        rdp_credssp_ts_request auth_response;
        rdp_credssp_ts_request pub_key_response;
        rdp_ntlm_authenticate_result ntlm_auth_result;
        rdp_ntlm_security_context ntlm_security;
        uint8_t client_nonce[32];

        rdp_buffer_init(&credssp_request);
        rdp_buffer_init(&credssp_reply);
        rdp_buffer_init(&ntlm_negotiate);
        rdp_buffer_init(&spnego_negotiate);
        rdp_buffer_init(&ntlm_authenticate);
        rdp_buffer_init(&spnego_authenticate);
        rdp_buffer_init(&tls_public_key);
        rdp_buffer_init(&pub_key_auth);
        rdp_buffer_init(&auth_info);
        memset(&ntlm_auth_result, 0, sizeof(ntlm_auth_result));
        memset(&ntlm_security, 0, sizeof(ntlm_security));
        memset(client_nonce, 0, sizeof(client_nonce));
        rdp_trace_event(RDP_TRACE_PROTOCOL, "credssp.nla.start", "state=begin");
        status = rdp_credssp_begin(true, &credssp_state);
        if (status == LIBRDP_STATUS_OK)
            status = RAND_bytes(client_nonce, (int)sizeof(client_nonce)) == 1 ? LIBRDP_STATUS_OK
                                                                              : LIBRDP_STATUS_PROTOCOL_ERROR;
        if (status == LIBRDP_STATUS_OK)
            status = rdp_transport_get_tls_public_key(&session->transport, &tls_public_key);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_credssp_write_ntlm_negotiate(&ntlm_negotiate,
                                                      "librdp",
                                                      librdp_settings_domain(session->settings));
        if (status == LIBRDP_STATUS_OK)
            status = rdp_credssp_write_spnego_ntlm_negotiate(&spnego_negotiate,
                                                             ntlm_negotiate.data,
                                                             ntlm_negotiate.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_credssp_write_ts_request(&credssp_request,
                                                  6,
                                                  spnego_negotiate.data,
                                                  spnego_negotiate.length,
                                                  NULL,
                                                  0,
                                                  NULL,
                                                  0,
                                                  client_nonce,
                                                  sizeof(client_nonce));
        if (status == LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "credssp.nla.negotiate",
                            "token_len=%u client_nonce_len=%u public_key_len=%u",
                            (unsigned)credssp_request.length,
                            (unsigned)sizeof(client_nonce),
                            (unsigned)tls_public_key.length);
            status = rdp_transport_write_all(&session->transport, credssp_request.data, credssp_request.length);
        }
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_read_credssp_ts_request(session, &credssp_reply, 5000);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_credssp_parse_ts_request(credssp_reply.data, credssp_reply.length, &ts_response);
        if (status == LIBRDP_STATUS_OK)
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "credssp.nla.challenge",
                            "version=%u token_len=%u error=%u",
                            ts_response.version,
                            (unsigned)ts_response.nego_token_len,
                            ts_response.has_error_code ? ts_response.error_code : 0);
        if (status == LIBRDP_STATUS_OK && ts_response.nego_token_len > 0)
        {
            const uint8_t* ntlm_token = NULL;
            size_t ntlm_token_len = 0;
            rdp_ntlm_challenge ntlm_challenge;

            status = rdp_credssp_extract_ntlm_challenge(ts_response.nego_token,
                                                        ts_response.nego_token_len,
                                                        &ntlm_token,
                                                        &ntlm_token_len);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_parse_ntlm_challenge(ntlm_token, ntlm_token_len, &ntlm_challenge);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.ntlm.challenge",
                                "flags=%u target_name_len=%u target_info_len=%u",
                                ntlm_challenge.flags,
                                (unsigned)ntlm_challenge.target_name_len,
                                (unsigned)ntlm_challenge.target_info_len);
            if (status == LIBRDP_STATUS_OK &&
                (!librdp_settings_username(session->settings) || !rdp_settings_password_internal(session->settings)))
                status = LIBRDP_STATUS_INVALID_ARGUMENT;
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_write_ntlm_authenticate(&ntlm_authenticate,
                                                             &ntlm_challenge,
                                                             librdp_settings_username(session->settings),
                                                             rdp_settings_password_internal(session->settings),
                                                             librdp_settings_domain(session->settings),
                                                             "librdp",
                                                             0,
                                                             NULL,
                                                             NULL,
                                                             &ntlm_auth_result);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_write_spnego_ntlm_authenticate(&spnego_authenticate,
                                                                    ntlm_authenticate.data,
                                                                    ntlm_authenticate.length);
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&credssp_request);
                rdp_buffer_init(&credssp_request);
                status = rdp_credssp_write_ts_request(&credssp_request,
                                                      ts_response.version ? ts_response.version : 6,
                                                      spnego_authenticate.data,
                                                      spnego_authenticate.length,
                                                      NULL,
                                                      0,
                                                      NULL,
                                                      0,
                                                      client_nonce,
                                                      sizeof(client_nonce));
            }
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.nla.authenticate",
                                "token_len=%u flags=%u",
                                (unsigned)credssp_request.length,
                                ntlm_auth_result.flags);
                status = rdp_transport_write_all(&session->transport, credssp_request.data, credssp_request.length);
            }
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_read_credssp_ts_request(session, &credssp_reply, 5000);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_parse_ts_request(credssp_reply.data, credssp_reply.length, &auth_response);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.nla.authenticate_response",
                                "version=%u token_len=%u auth_info_len=%u pub_key_auth_len=%u error=%u",
                                auth_response.version,
                                (unsigned)auth_response.nego_token_len,
                                (unsigned)auth_response.auth_info_len,
                                (unsigned)auth_response.pub_key_auth_len,
                                auth_response.has_error_code ? auth_response.error_code : 0);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_ntlm_security_init(&ntlm_security, &ntlm_auth_result);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_encrypt_public_key_hash(&ntlm_security,
                                                             client_nonce,
                                                             sizeof(client_nonce),
                                                             tls_public_key.data,
                                                             tls_public_key.length,
                                                             &pub_key_auth);
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&credssp_request);
                rdp_buffer_init(&credssp_request);
                status = rdp_credssp_write_ts_request(&credssp_request,
                                                      auth_response.version ? auth_response.version : 6,
                                                      NULL,
                                                      0,
                                                      NULL,
                                                      0,
                                                      pub_key_auth.data,
                                                      pub_key_auth.length,
                                                      client_nonce,
                                                      sizeof(client_nonce));
            }
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.nla.pubkey",
                                "token_len=%u pub_key_auth_len=%u",
                                (unsigned)credssp_request.length,
                                (unsigned)pub_key_auth.length);
                status = rdp_transport_write_all(&session->transport, credssp_request.data, credssp_request.length);
            }
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_read_credssp_ts_request(session, &credssp_reply, 5000);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_parse_ts_request(credssp_reply.data, credssp_reply.length, &pub_key_response);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.nla.pubkey_response",
                                "version=%u token_len=%u auth_info_len=%u pub_key_auth_len=%u error=%u",
                                pub_key_response.version,
                                (unsigned)pub_key_response.nego_token_len,
                                (unsigned)pub_key_response.auth_info_len,
                                (unsigned)pub_key_response.pub_key_auth_len,
                                pub_key_response.has_error_code ? pub_key_response.error_code : 0);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_verify_public_key_hash(&ntlm_security,
                                                            client_nonce,
                                                            sizeof(client_nonce),
                                                            tls_public_key.data,
                                                            tls_public_key.length,
                                                            pub_key_response.pub_key_auth,
                                                            pub_key_response.pub_key_auth_len);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_PROTOCOL, "credssp.nla.pubkey.verified", "pub_key_auth_len=%u",
                                (unsigned)pub_key_response.pub_key_auth_len);
            if (status == LIBRDP_STATUS_OK)
                status = rdp_credssp_encrypt_password_credentials(&ntlm_security,
                                                                  librdp_settings_domain(session->settings),
                                                                  librdp_settings_username(session->settings),
                                                                  rdp_settings_password_internal(session->settings),
                                                                  &auth_info);
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&credssp_request);
                rdp_buffer_init(&credssp_request);
                status = rdp_credssp_write_ts_request(&credssp_request,
                                                      pub_key_response.version ? pub_key_response.version : 6,
                                                      NULL,
                                                      0,
                                                      auth_info.data,
                                                      auth_info.length,
                                                      NULL,
                                                      0,
                                                      client_nonce,
                                                      sizeof(client_nonce));
            }
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "credssp.nla.credentials",
                                "token_len=%u auth_info_len=%u",
                                (unsigned)credssp_request.length,
                                (unsigned)auth_info.length);
                status = rdp_transport_write_all(&session->transport, credssp_request.data, credssp_request.length);
            }
        }
        rdp_buffer_free(&auth_info);
        rdp_buffer_free(&pub_key_auth);
        rdp_buffer_free(&tls_public_key);
        rdp_buffer_free(&spnego_authenticate);
        rdp_buffer_free(&ntlm_authenticate);
        rdp_buffer_free(&spnego_negotiate);
        rdp_buffer_free(&ntlm_negotiate);
        rdp_buffer_free(&credssp_reply);
        rdp_buffer_free(&credssp_request);
        OPENSSL_cleanse(&ntlm_security, sizeof(ntlm_security));
        OPENSSL_cleanse(client_nonce, sizeof(client_nonce));
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL, "credssp.nla.failed", "status=%d", (int)status);
            goto fail;
        }
        credssp_state = RDP_CREDSSP_COMPLETE;
        rdp_trace_event(RDP_TRACE_PROTOCOL, "credssp.nla.done", "state=%u", (unsigned)credssp_state);
    }

    {
        rdp_gcc_client_config config;
        memset(&config, 0, sizeof(config));
        config.desktop_width = (uint16_t)librdp_settings_width(session->settings);
        config.desktop_height = (uint16_t)librdp_settings_height(session->settings);
        config.requested_protocols = selected_protocol;
        config.client_version = RDP_GCC_CLIENT_VERSION_10_12;
        config.early_capability_flags = RDP_GCC_EARLY_SUPPORT_ERRINFO | RDP_GCC_EARLY_WANT_32BPP |
                                        RDP_GCC_EARLY_SUPPORT_STATUSINFO |
                                        RDP_GCC_EARLY_SUPPORT_MONITOR_LAYOUT |
                                        RDP_GCC_EARLY_SUPPORT_NETCHAR_AUTODETECT |
                                        RDP_GCC_EARLY_SUPPORT_DYNVC_GFX;
        config.supported_color_depths = RDP_GCC_SUPPORTED_COLOR_DEPTHS_32BPP;
        config.connection_type = RDP_GCC_CONNECTION_TYPE_LAN;
        config.desktop_physical_width = rdp_session_pixels_to_mm(config.desktop_width);
        config.desktop_physical_height = rdp_session_pixels_to_mm(config.desktop_height);
        config.desktop_scale_factor = 100;
        config.device_scale_factor = 100;
        config.client_name = "librdp";
        config.enable_dynamic_channels = 1;

        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "mcs.connect.initial",
                        "width=%u height=%u selected_protocol=%u dynamic_channels=%u early_capability_flags=%u",
                        (unsigned)config.desktop_width,
                        (unsigned)config.desktop_height,
                        config.requested_protocols,
                        (unsigned)config.enable_dynamic_channels,
                        (unsigned)config.early_capability_flags);
        status = rdp_gcc_write_client_data_blocks(&gcc_blocks, &config);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        status = rdp_gcc_write_conference_create_request(&gcc_request, gcc_blocks.data, gcc_blocks.length);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        status = rdp_mcs_write_connect_initial(&mcs, gcc_request.data, gcc_request.length);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }

    rdp_buffer_free(&request);
    rdp_buffer_init(&request);
    status = rdp_session_write_mcs_pdu(session, &mcs, "mcs.connect.initial", 1);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    rdp_buffer_free(&reply);
    rdp_buffer_init(&reply);
    status = rdp_session_read_mcs_pdu(session, &reply, &mcs_pdu, &mcs_pdu_len, "mcs.connect.response");
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    status = rdp_mcs_parse_connect_response(mcs_pdu, mcs_pdu_len, &mcs_response);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    if (!mcs_response.has_result || mcs_response.result != 0)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.connect.response.failed", "result=%u", mcs_response.result);
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto fail;
    }
    rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.connect.response", "result=%u", mcs_response.result);
    if (mcs_response.user_data_len > 0)
    {
        status = rdp_gcc_parse_conference_create_response(mcs_response.user_data,
                                                          mcs_response.user_data_len,
                                                          &gcc_response);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        if (gcc_response.result != 0)
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL, "gcc.conference.response.failed", "result=%u", gcc_response.result);
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
            goto fail;
        }
        status = rdp_gcc_parse_server_data_blocks(gcc_response.user_data, gcc_response.user_data_len, &server_data);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        server_encryption_method = server_data.encryption_method;
        server_encryption_level = server_data.encryption_level;
        if (server_data.server_random_len > 0)
        {
            status = rdp_buffer_append(&server_random, server_data.server_random, server_data.server_random_len);
            if (status != LIBRDP_STATUS_OK)
                goto fail;
        }
        if (server_data.server_certificate_len > 0)
        {
            status = rdp_buffer_append(&server_certificate,
                                       server_data.server_certificate,
                                       server_data.server_certificate_len);
            if (status != LIBRDP_STATUS_OK)
                goto fail;
        }
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "gcc.conference.response",
                        "node_id=%u tag=%u user_data_len=%u",
                        gcc_response.node_id,
                        gcc_response.tag,
                        (unsigned)gcc_response.user_data_len);
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "gcc.server.core",
                        "version=%u requested_protocols=%u early_capability_flags=%u",
                        server_data.version,
                        server_data.requested_protocols,
                        server_data.early_capability_flags);
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "gcc.server.security",
                        "encryption_method=%u encryption_level=%u random_len=%u certificate_len=%u",
                        server_data.encryption_method,
                        server_data.encryption_level,
                        server_data.server_random_len,
                        server_data.server_certificate_len);
        if (server_data.has_network)
        {
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "gcc.server.network",
                            "mcs_channel_id=%u channel_count=%u",
                            server_data.mcs_channel_id,
                            server_data.channel_count);
            if (server_data.channel_count > 0)
            {
                session->dynamic_channel_id = server_data.channel_ids[0];
                rdp_trace_event(RDP_TRACE_CLIENT,
                                "client.drdynvc.channel",
                                "channel_id=%u",
                                session->dynamic_channel_id);
            }
        }
    }

    rdp_buffer_free(&mcs);
    rdp_buffer_init(&mcs);
    status = rdp_mcs_write_erect_domain_request(&mcs);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.erect_domain.request", "sub_height=0 sub_interval=0");
    status = rdp_session_write_mcs_pdu(session, &mcs, "mcs.erect_domain.request", 1);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    rdp_buffer_free(&mcs);
    rdp_buffer_init(&mcs);
    status = rdp_mcs_write_attach_user_request(&mcs);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.attach_user.request", "message=sent");
    status = rdp_session_write_mcs_pdu(session, &mcs, "mcs.attach_user.request", 1);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    rdp_buffer_free(&reply);
    rdp_buffer_init(&reply);
    status = rdp_session_read_mcs_pdu(session, &reply, &mcs_pdu, &mcs_pdu_len, "mcs.attach_user.confirm");
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    status = rdp_mcs_parse_attach_user_confirm(mcs_pdu, mcs_pdu_len, &attach_confirm);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    if (attach_confirm.result != 0)
    {
        rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.attach_user.failed", "result=%u", attach_confirm.result);
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
        goto fail;
    }
    session->mcs_user_id = attach_confirm.user_id;
    rdp_trace_event(RDP_TRACE_PROTOCOL, "mcs.attach_user.confirm", "result=0 user_id=%u", session->mcs_user_id);

    status = rdp_session_join_mcs_channel(session, session->mcs_user_id, "user", &mcs, &reply);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    status = rdp_session_join_mcs_channel(session, (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID, "global", &mcs, &reply);
    if (status != LIBRDP_STATUS_OK)
        goto fail;

    if (session->dynamic_channel_id != 0 && session->dynamic_channel_id != session->mcs_user_id &&
        session->dynamic_channel_id != RDP_MCS_GLOBAL_CHANNEL_ID)
    {
        status = rdp_session_join_mcs_channel(session, session->dynamic_channel_id, "drdynvc", &mcs, &reply);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }

    if (selected_protocol == RDP_X224_PROTOCOL_STANDARD &&
        (server_encryption_method != 0 || server_encryption_level != 0))
    {
        uint8_t client_random[RDP_SECURITY_CLIENT_RANDOM_LEN];
        rdp_security_public_key public_key;
        rdp_buffer encrypted_client_random;

        memset(&public_key, 0, sizeof(public_key));
        rdp_buffer_init(&encrypted_client_random);
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "rdp.security_exchange.start",
                        "encryption_method=%u encryption_level=%u random_len=%u certificate_len=%u",
                        server_encryption_method,
                        server_encryption_level,
                        (unsigned)server_random.length,
                        (unsigned)server_certificate.length);
        if (server_random.length != RDP_SECURITY_CLIENT_RANDOM_LEN || server_certificate.length == 0)
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        else
            status = rdp_security_parse_server_certificate(server_certificate.data, server_certificate.length, &public_key);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_security_generate_client_random(client_random);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_security_encrypt_client_random(&public_key, client_random, &encrypted_client_random);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_security_standard_client_init(&session->standard_security,
                                                       server_encryption_method,
                                                       client_random,
                                                       server_random.data);
        memset(client_random, 0, sizeof(client_random));
        if (status == LIBRDP_STATUS_OK)
            status = rdp_security_write_exchange_pdu(&security_payload,
                                                     encrypted_client_random.data,
                                                     encrypted_client_random.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_security_write_send_data_request(&security_data,
                                                          session->mcs_user_id,
                                                          (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                          security_payload.data,
                                                          security_payload.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_session_write_mcs_pdu(session, &security_data, "rdp.security_exchange.pdu", 0);
        if (status == LIBRDP_STATUS_OK)
        {
            standard_security_ready = 1;
            session->standard_security_active = 1;
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "rdp.security_exchange.done",
                            "encrypted_random_len=%u",
                            (unsigned)encrypted_client_random.length);
        }
        rdp_security_public_key_clear(&public_key);
        rdp_buffer_free(&encrypted_client_random);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
        rdp_buffer_free(&security_payload);
        rdp_buffer_free(&security_data);
        rdp_buffer_init(&security_payload);
        rdp_buffer_init(&security_data);
    }

    {
        rdp_client_info info;
        memset(&info, 0, sizeof(info));
        info.domain = librdp_settings_domain(session->settings);
        info.username = librdp_settings_username(session->settings);
        info.password = rdp_settings_password_internal(session->settings);
        info.alternate_shell = NULL;
        info.working_dir = NULL;
        if (standard_security_ready)
            status = rdp_security_write_encrypted_client_info_pdu(&security_payload,
                                                                  &session->standard_security,
                                                                  &info);
        else
            status = rdp_security_write_client_info_pdu(&security_payload, &info);
        if (status != LIBRDP_STATUS_OK)
            goto fail;
    }
    status = rdp_security_write_send_data_request(&security_data,
                                                  session->mcs_user_id,
                                                  (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                                                  security_payload.data,
                                                  security_payload.length);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_event(RDP_TRACE_PROTOCOL,
                    "rdp.client_info.start",
                    "domain_present=%u username_present=%u password=masked encrypted=%u",
                    librdp_settings_domain(session->settings) ? 1u : 0u,
                    librdp_settings_username(session->settings) ? 1u : 0u,
                    standard_security_ready ? 1u : 0u);
    status = rdp_session_write_mcs_pdu(session, &security_data, "rdp.client_info.pdu", 0);
    if (status != LIBRDP_STATUS_OK)
        goto fail;
    rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.client_info.done", "status=sent");

    rdp_session_set_state(session, LIBRDP_SESSION_CONNECTED);

    rdp_session_emit_surface_invalidated(session,
                                         0,
                                         0,
                                         librdp_surface_width(session->surface),
                                         librdp_surface_height(session->surface));
    rdp_session_pointer_emit_default(session);

    rdp_trace_event(RDP_TRACE_CLIENT, "client.connect.done", "transport=tcp");
    rdp_buffer_free(&reply);
    rdp_buffer_free(&request);
    rdp_buffer_free(&server_certificate);
    rdp_buffer_free(&server_random);
    rdp_buffer_free(&security_data);
    rdp_buffer_free(&security_payload);
    rdp_buffer_free(&mcs);
    rdp_buffer_free(&gcc_request);
    rdp_buffer_free(&gcc_blocks);
    rdp_buffer_free(&x224);
    return LIBRDP_STATUS_OK;

fail:
    rdp_transport_close(&session->transport);
    rdp_security_standard_clear(&session->standard_security);
    session->standard_security_active = 0;
    rdp_trace_event(RDP_TRACE_CLIENT, "client.connect.failed", "status=%d", (int)status);
    rdp_buffer_free(&reply);
    rdp_buffer_free(&request);
    rdp_buffer_free(&server_certificate);
    rdp_buffer_free(&server_random);
    rdp_buffer_free(&security_data);
    rdp_buffer_free(&security_payload);
    rdp_buffer_free(&mcs);
    rdp_buffer_free(&gcc_request);
    rdp_buffer_free(&gcc_blocks);
    rdp_buffer_free(&x224);
    return rdp_session_fail(session, status);
}

librdp_status librdp_session_run_once(librdp_session* session, int timeout_ms)
{
    short revents = 0;
    rdp_buffer packet;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || timeout_ms < 0)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&packet);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.active.loop.start", "timeout_ms=%d", timeout_ms);
    if (session->state == LIBRDP_SESSION_CONNECTED)
        rdp_session_set_state(session, LIBRDP_SESSION_ACTIVE);

    status = rdp_transport_wait(&session->transport, timeout_ms, POLLIN, &revents);
    if (status == LIBRDP_STATUS_TIMEOUT)
    {
        rdp_trace_event(RDP_TRACE_CLIENT, "client.active.loop.done", "status=timeout");
        return LIBRDP_STATUS_OK;
    }
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&packet);
        return status;
    }
    if ((revents & POLLIN) != 0)
    {
        uint8_t first_byte = 0;
        size_t peeked = 0;

        status = rdp_transport_peek(&session->transport, &first_byte, 1, &peeked);
        if (status == LIBRDP_STATUS_CLOSED)
        {
            rdp_buffer_free(&packet);
            return librdp_session_disconnect(session);
        }
        if (status != LIBRDP_STATUS_OK || peeked != 1)
        {
            rdp_buffer_free(&packet);
            return rdp_session_fail(session, status == LIBRDP_STATUS_OK ? LIBRDP_STATUS_IO_ERROR : status);
        }
        if (first_byte != 3)
        {
            status = rdp_session_read_fastpath_packet(session, &packet);
            if (status == LIBRDP_STATUS_CLOSED)
            {
                rdp_buffer_free(&packet);
                return librdp_session_disconnect(session);
            }
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_process_fastpath_packet(session, &packet);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            goto done;
        }
        const uint8_t* pdu = NULL;
        size_t pdu_len = 0;
        rdp_mcs_send_data_indication indication;
        rdp_slowpath_share_control_header slow_header;
        rdp_buffer security_payload;
        const uint8_t* indication_payload = NULL;
        size_t indication_payload_len = 0;
        uint16_t security_flags = 0;
        int have_slow_header = 0;

        rdp_buffer_init(&security_payload);
        status = rdp_session_read_mcs_pdu(session, &packet, &pdu, &pdu_len, "rdp.slowpath.pdu");
        if (status == LIBRDP_STATUS_CLOSED)
        {
            rdp_buffer_free(&security_payload);
            rdp_buffer_free(&packet);
            return librdp_session_disconnect(session);
        }
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&security_payload);
            rdp_buffer_free(&packet);
            return rdp_session_fail(session, status);
        }
        status = rdp_mcs_parse_send_data_indication(pdu, pdu_len, &indication);
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_buffer_free(&security_payload);
            rdp_buffer_free(&packet);
            return rdp_session_fail(session, status);
        }
        indication_payload = indication.payload;
        indication_payload_len = indication.payload_len;
        if (session->standard_security_active)
        {
            status = rdp_security_unwrap_pdu(&session->standard_security,
                                             indication.payload,
                                             indication.payload_len,
                                             &security_payload,
                                             &security_flags);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            indication_payload = security_payload.data;
            indication_payload_len = security_payload.length;
        }
        rdp_trace_event(RDP_TRACE_PROTOCOL,
                        "mcs.send_data.indication",
                        "initiator=%u channel_id=%u payload_len=%u security_flags=%u",
                        indication.initiator,
                        indication.channel_id,
                        (unsigned)indication_payload_len,
                        security_flags);
        if (session->dynamic_channel_id != 0 && indication.channel_id == session->dynamic_channel_id)
        {
            rdp_virtual_channel_packet channel_packet;

            status = rdp_virtual_channel_parse_packet(indication_payload, indication_payload_len, &channel_packet);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_trace_event(RDP_TRACE_CLIENT,
                            "client.drdynvc.data",
                            "channel_id=%u flags=%u payload_len=%u",
                            indication.channel_id,
                            channel_packet.flags,
                            (unsigned)channel_packet.payload_len);
            status = rdp_session_handle_dynamic_channel(session, &channel_packet);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_buffer_free(&security_payload);
            goto done;
        }
        status = rdp_slowpath_parse_share_control_header(indication_payload, indication_payload_len, &slow_header);
        if (status == LIBRDP_STATUS_OK)
            have_slow_header = 1;
        if (status != LIBRDP_STATUS_OK)
        {
            rdp_license_error_alert alert;
            librdp_status license_status = rdp_license_parse_error_alert(indication_payload,
                                                                         indication_payload_len,
                                                                         &alert);
            if (license_status == LIBRDP_STATUS_OK)
            {
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.licensing.error_alert",
                                "type=%u flags=%u error=%u state=%u blob_type=%u blob_len=%u",
                                alert.message_type,
                                alert.flags,
                                alert.error_code,
                                alert.state_transition,
                                alert.blob_type,
                                alert.blob_length);
                status = LIBRDP_STATUS_OK;
            }
        }
        if (have_slow_header && status == LIBRDP_STATUS_OK &&
            (slow_header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_DEMAND_ACTIVE)
        {
            rdp_slowpath_demand_active demand;
            rdp_buffer confirm;

            rdp_buffer_init(&confirm);
            status = rdp_slowpath_parse_demand_active(indication_payload, indication_payload_len, &demand);
            if (status == LIBRDP_STATUS_OK)
                rdp_trace_event(RDP_TRACE_PROTOCOL,
                                "rdp.activation.demand_active",
                                "share_id=%u capabilities=%u",
                                demand.share_id,
                                demand.capabilities.count);
            if (status == LIBRDP_STATUS_OK)
                session->share_id = demand.share_id;
            if (status == LIBRDP_STATUS_OK)
            {
                rdp_session_pointer_cache_clear(session);
                rdp_session_pointer_emit_default(session);
            }
            if (status == LIBRDP_STATUS_OK)
                status = rdp_slowpath_write_confirm_active(&confirm,
                                                           demand.share_id,
                                                           session->mcs_user_id,
                                                           (uint16_t)librdp_surface_width(session->surface),
                                                           (uint16_t)librdp_surface_height(session->surface),
                                                           "librdp");
            if (status == LIBRDP_STATUS_OK)
                status = rdp_session_write_slowpath_pdu(session, &confirm, "rdp.activation.confirm_active");
            rdp_buffer_free(&confirm);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.activation.confirm_active", "share_id=%u", demand.share_id);
            status = rdp_session_send_activation_finalization(session, demand.share_id);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
        }
        else if (have_slow_header && status == LIBRDP_STATUS_OK &&
                 (slow_header.pdu_type & 0x000fu) == RDP_SLOWPATH_PDU_TYPE_DATA)
        {
            rdp_slowpath_data_pdu data_pdu;

            status = rdp_slowpath_parse_data_pdu(indication_payload, indication_payload_len, &data_pdu);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&security_payload);
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            rdp_trace_event(RDP_TRACE_PROTOCOL,
                            "rdp.slowpath.data",
                            "type=%u compressed_type=%u payload_len=%u",
                            data_pdu.pdu_type2,
                            data_pdu.compressed_type,
                            (unsigned)data_pdu.payload_len);
            status = rdp_session_trace_slowpath_data_pdu(session, &data_pdu);
            if (status != LIBRDP_STATUS_OK)
            {
                rdp_buffer_free(&packet);
                return rdp_session_fail(session, status);
            }
            if (data_pdu.pdu_type2 == RDP_SLOWPATH_DATA_PDU_UPDATE)
            {
                if (data_pdu.compressed_type != 0)
                {
                    rdp_trace_event(RDP_TRACE_PROTOCOL,
                                    "rdp.slowpath.update.unsupported",
                                    "compressed_type=%u payload_len=%u",
                                    data_pdu.compressed_type,
                                    (unsigned)data_pdu.payload_len);
                }
                else
                {
                    rdp_stream update_stream;
                    uint16_t update_type = 0;

                    rdp_stream_init(&update_stream, data_pdu.payload, data_pdu.payload_len);
                    if (rdp_stream_read_u16_le(&update_stream, &update_type) != LIBRDP_STATUS_OK)
                    {
                        rdp_buffer_free(&security_payload);
                        rdp_buffer_free(&packet);
                        return rdp_session_fail(session, LIBRDP_STATUS_PROTOCOL_ERROR);
                    }
                    rdp_trace_event(RDP_TRACE_PROTOCOL,
                                    "rdp.slowpath.update",
                                    "update_type=%u payload_len=%u",
                                    update_type,
                                    (unsigned)data_pdu.payload_len);
                    if (update_type == RDP_UPDATE_TYPE_BITMAP)
                    {
                        rdp_bitmap_update update;

                        status = rdp_bitmap_parse_update(data_pdu.payload, data_pdu.payload_len, &update);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_session_apply_bitmap_update(session, &update);
                        if (status != LIBRDP_STATUS_OK)
                        {
                            rdp_buffer_free(&security_payload);
                            rdp_buffer_free(&packet);
                            return rdp_session_fail(session, status);
                        }
                        rdp_trace_event(RDP_TRACE_PROTOCOL, "rdp.slowpath.bitmap_update", "rectangles=%u", update.count);
                    }
                    else if (update_type == RDP_UPDATE_TYPE_POINTER)
                    {
                        rdp_pointer_update pointer;

                        status = rdp_pointer_parse_slowpath(data_pdu.payload + 2u, data_pdu.payload_len - 2u, &pointer);
                        if (status == LIBRDP_STATUS_OK)
                            status = rdp_session_pointer_apply_update(session, &pointer);
                        if (status != LIBRDP_STATUS_OK)
                        {
                            rdp_buffer_free(&security_payload);
                            rdp_buffer_free(&packet);
                            return rdp_session_fail(session, status);
                        }
                        rdp_trace_event(RDP_TRACE_PROTOCOL,
                                        "rdp.slowpath.pointer",
                                        "kind=%u cache_index=%u width=%u height=%u",
                                        pointer.kind,
                                        pointer.cache_index,
                                        pointer.width,
                                        pointer.height);
                    }
                    else
                    {
                        rdp_trace_event(RDP_TRACE_PROTOCOL,
                                        "rdp.slowpath.update.unsupported",
                                        "update_type=%u payload_len=%u",
                                        update_type,
                                        (unsigned)data_pdu.payload_len);
                    }
                }
            }
        }
        rdp_buffer_free(&security_payload);
    }

done:
    rdp_buffer_free(&packet);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.active.loop.done", "status=idle");
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_disconnect(librdp_session* session)
{
    librdp_event event;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state == LIBRDP_SESSION_CLOSED || session->state == LIBRDP_SESSION_IDLE)
        return LIBRDP_STATUS_OK;

    rdp_trace_event(RDP_TRACE_CLIENT, "client.disconnect.start", "state=%d", (int)session->state);
    rdp_session_set_state(session, LIBRDP_SESSION_CLOSING);
    rdp_session_graphics_dirty_reset(session);
    rdp_transport_close(&session->transport);
    rdp_security_standard_clear(&session->standard_security);
    session->standard_security_active = 0;
    session->core_input_channel_id = 0;
    session->core_input_channel_id_bytes = 0;
    session->core_input_ready = 0;
    session->display_control_channel_id = 0;
    session->display_control_channel_id_bytes = 0;
    session->display_control_ready = 0;
    session->sent_desktop_width = 0;
    session->sent_desktop_height = 0;
    memset(&session->display_control_caps, 0, sizeof(session->display_control_caps));
    session->graphics_channel_id = 0;
    session->graphics_channel_id_bytes = 0;
    session->graphics_ready = 0;
    session->graphics_selected_version = 0;
    session->graphics_selected_flags = 0;
    session->graphics_frames_decoded = 0;
    session->mouse_cursor_channel_id = 0;
    session->mouse_cursor_channel_id_bytes = 0;
    session->mouse_cursor_ready = 0;
    rdp_graphics_decompressor_reset(&session->graphics_decompressor);
    rdp_clearcodec_context_reset(&session->clearcodec);
    rdp_session_graphics_surfaces_clear(session);
    rdp_session_graphics_cache_clear(session);
    rdp_session_pointer_cache_clear(session);
    rdp_session_dynamic_channels_clear(session);
    rdp_session_set_state(session, LIBRDP_SESSION_CLOSED);

    event.type = LIBRDP_EVENT_DISCONNECTED;
    rdp_session_emit(session, &event);
    rdp_trace_event(RDP_TRACE_CLIENT, "client.disconnect.done", "status=ok");
    return LIBRDP_STATUS_OK;
}

librdp_status librdp_session_resize(librdp_session* session, uint32_t width, uint32_t height)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session)
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    status = rdp_session_request_display_control_layout(session, width, height);
    return status == LIBRDP_STATUS_OK ? LIBRDP_STATUS_OK : status;
}

librdp_status librdp_session_refresh(librdp_session* session, uint32_t x, uint32_t y, uint32_t width, uint32_t height)
{
    rdp_buffer refresh;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!session || width == 0 || height == 0 || x > 0xffffu || y > 0xffffu ||
        width > 0xffffu || height > 0xffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (x + width - 1u > 0xffffu || y + height - 1u > 0xffffu)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->share_id == 0)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&refresh);
    status = rdp_slowpath_write_client_refresh_rect(&refresh,
                                                    session->share_id,
                                                    session->mcs_user_id,
                                                    (uint16_t)x,
                                                    (uint16_t)y,
                                                    (uint16_t)width,
                                                    (uint16_t)height);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_session_write_slowpath_pdu(session, &refresh, "rdp.refresh_rect");
    rdp_buffer_free(&refresh);
    if (status == LIBRDP_STATUS_OK)
        rdp_trace_event(RDP_TRACE_CLIENT,
                        "client.active.refresh_rect",
                        "x=%u y=%u width=%u height=%u",
                        x,
                        y,
                        width,
                        height);
    return status;
}

librdp_status librdp_session_send_key(librdp_session* session, const librdp_key_event* key)
{
    uint16_t flags = 0;
    rdp_buffer input;
    librdp_event event;
    librdp_status status = LIBRDP_STATUS_OK;
    const int use_unicode = key && ((key->flags & LIBRDP_KEY_FLAG_UNICODE) != 0);
    const int use_core_input = key && !use_unicode && (key->flags & (LIBRDP_KEY_FLAG_EXTENDED | LIBRDP_KEY_FLAG_EXTENDED1)) == 0 &&
                               session && session->core_input_ready;

    if (!session || !key)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->share_id == 0)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&input);
    if (use_core_input)
    {
        if (key->scancode > 0xffu)
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
        else
            status = rdp_core_input_write_keyboard_event(&input,
                                                        (uint8_t)key->scancode,
                                                        key->state == LIBRDP_KEY_RELEASED ? 1u : 0u);
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

librdp_status librdp_session_send_mouse(librdp_session* session, const librdp_mouse_event* mouse)
{
    uint16_t flags = 0;
    rdp_buffer input;
    librdp_event event;
    librdp_status status = LIBRDP_STATUS_OK;
    int use_extended = 0;

    if (!session || !mouse)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (session->state != LIBRDP_SESSION_CONNECTED && session->state != LIBRDP_SESSION_ACTIVE)
        return LIBRDP_STATUS_STATE;
    if (session->share_id == 0)
        return LIBRDP_STATUS_STATE;

    rdp_buffer_init(&input);
    use_extended = rdp_input_mouse_uses_extended(mouse);
    status = rdp_input_make_pointer_flags(mouse, &flags);
    if (status == LIBRDP_STATUS_OK)
    {
        if (use_extended)
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
        if (use_extended)
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
                    use_extended ? "slowpath_mousex" : "slowpath",
                    flags);
    rdp_buffer_free(&input);
    return LIBRDP_STATUS_OK;
}

librdp_session_state librdp_session_get_state(const librdp_session* session)
{
    return session ? session->state : LIBRDP_SESSION_FAILED;
}

const librdp_surface* librdp_session_get_surface(const librdp_session* session)
{
    return session ? session->surface : NULL;
}
