/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_INPUT_H
#define LIBRDP_INPUT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Pressed or released state for keyboard input events.
 *
 * Values are copied into input PDUs and are not retained by the library after
 * the send call returns.
 *
 * @since 0.1.0
 */
typedef enum librdp_key_state
{
    LIBRDP_KEY_RELEASED = 0, /**< Key release transition. */
    LIBRDP_KEY_PRESSED = 1   /**< Key press transition. */
} librdp_key_state;

/**
 * @brief Logical mouse button or wheel action for pointer input events.
 *
 * Wheel values represent discrete vertical or horizontal wheel actions.
 *
 * @since 0.1.0
 */
typedef enum librdp_mouse_button
{
    LIBRDP_MOUSE_BUTTON_NONE = 0,        /**< Pointer movement without a button transition. */
    LIBRDP_MOUSE_BUTTON_LEFT = 1,        /**< Primary pointer button. */
    LIBRDP_MOUSE_BUTTON_RIGHT = 2,       /**< Secondary pointer button. */
    LIBRDP_MOUSE_BUTTON_MIDDLE = 3,      /**< Middle pointer button. */
    LIBRDP_MOUSE_BUTTON_WHEEL_UP = 4,    /**< Vertical wheel step toward the top. */
    LIBRDP_MOUSE_BUTTON_WHEEL_DOWN = 5,  /**< Vertical wheel step toward the bottom. */
    LIBRDP_MOUSE_BUTTON_WHEEL_LEFT = 6,  /**< Horizontal wheel step toward the left. */
    LIBRDP_MOUSE_BUTTON_WHEEL_RIGHT = 7, /**< Horizontal wheel step toward the right. */
    LIBRDP_MOUSE_BUTTON_X1 = 8,          /**< First extended pointer button. */
    LIBRDP_MOUSE_BUTTON_X2 = 9           /**< Second extended pointer button. */
} librdp_mouse_button;

/**
 * @brief Pointer transition type for mouse input events.
 *
 * Movement events use LIBRDP_MOUSE_MOVED and typically pair with
 * LIBRDP_MOUSE_BUTTON_NONE.
 *
 * @since 0.1.0
 */
typedef enum librdp_mouse_state
{
    LIBRDP_MOUSE_RELEASED = 0, /**< Button release transition. */
    LIBRDP_MOUSE_PRESSED = 1,  /**< Button press transition. */
    LIBRDP_MOUSE_MOVED = 2     /**< Pointer position update. */
} librdp_mouse_state;

/**
 * @brief Keyboard event supplied to librdp_session_send_key().
 *
 * The structure is copied during the send call. Scancode events use scancode
 * and flags; Unicode events set LIBRDP_KEY_FLAG_UNICODE and use unicode.
 *
 * @since 0.1.0
 */
typedef struct librdp_key_event
{
    uint32_t scancode;       /**< RDP set-1 scancode for non-Unicode events. */
    librdp_key_state state;  /**< Press or release transition. */
    uint32_t flags;          /**< Bitmask of LIBRDP_KEY_FLAG_* values. */
    uint32_t unicode;        /**< UTF-16 code unit used when LIBRDP_KEY_FLAG_UNICODE is set. */
} librdp_key_event;

#define LIBRDP_KEY_FLAG_EXTENDED 0x00000001u  /**< Keyboard event uses the extended scancode prefix. */
#define LIBRDP_KEY_FLAG_EXTENDED1 0x00000002u /**< Keyboard event uses the extended1 scancode prefix. */
#define LIBRDP_KEY_FLAG_UNICODE 0x00000004u   /**< Keyboard event carries a UTF-16 code unit. */

/**
 * @brief Pointer event supplied to librdp_session_send_mouse().
 *
 * Coordinates are desktop pixel coordinates in the current remote desktop
 * coordinate space. The structure is copied during the send call.
 *
 * @since 0.1.0
 */
typedef struct librdp_mouse_event
{
    uint16_t x;                 /**< Pointer x coordinate. */
    uint16_t y;                 /**< Pointer y coordinate. */
    librdp_mouse_button button; /**< Button or wheel action associated with the event. */
    librdp_mouse_state state;   /**< Movement, press, or release state. */
} librdp_mouse_event;

#define LIBRDP_TOUCH_CONTACTRECT_PRESENT 0x0001u /**< Touch contact rectangle fields are valid. */
#define LIBRDP_TOUCH_ORIENTATION_PRESENT 0x0002u /**< Touch orientation field is valid. */
#define LIBRDP_TOUCH_PRESSURE_PRESENT 0x0004u    /**< Touch pressure field is valid. */

#define LIBRDP_PEN_FLAGS_PRESENT 0x0001u    /**< Pen flags field is valid. */
#define LIBRDP_PEN_PRESSURE_PRESENT 0x0002u /**< Pen pressure field is valid. */
#define LIBRDP_PEN_ROTATION_PRESENT 0x0004u /**< Pen rotation field is valid. */
#define LIBRDP_PEN_TILTX_PRESENT 0x0008u    /**< Pen tilt_x field is valid. */
#define LIBRDP_PEN_TILTY_PRESENT 0x0010u    /**< Pen tilt_y field is valid. */

#define LIBRDP_CONTACT_DOWN 0x00000001u      /**< Contact begins in this frame. */
#define LIBRDP_CONTACT_UPDATE 0x00000002u    /**< Contact updates in this frame. */
#define LIBRDP_CONTACT_UP 0x00000004u        /**< Contact ends in this frame. */
#define LIBRDP_CONTACT_INRANGE 0x00000008u   /**< Contact is within sensor range. */
#define LIBRDP_CONTACT_INCONTACT 0x00000010u /**< Contact is touching the surface. */
#define LIBRDP_CONTACT_CANCELED 0x00000020u  /**< Contact was canceled. */

#define LIBRDP_PEN_BARREL_PRESSED 0x00000001u /**< Pen barrel button is pressed. */
#define LIBRDP_PEN_ERASER_PRESSED 0x00000002u /**< Pen eraser button is pressed. */
#define LIBRDP_PEN_INVERTED 0x00000004u       /**< Pen is inverted. */

/**
 * @brief One touch contact in a multi-touch frame.
 *
 * Optional fields are valid only when their corresponding fields_present bit is
 * set. The structure is copied during the send call.
 *
 * @since 0.1.0
 */
typedef struct librdp_touch_contact
{
    uint8_t contact_id;          /**< Contact identifier stable across a gesture. */
    uint16_t fields_present;     /**< Bitmask of LIBRDP_TOUCH_*_PRESENT values. */
    int32_t x;                   /**< Contact x coordinate. */
    int32_t y;                   /**< Contact y coordinate. */
    uint32_t contact_flags;      /**< Bitmask of LIBRDP_CONTACT_* values. */
    int16_t contact_rect_left;   /**< Optional contact rectangle left offset. */
    int16_t contact_rect_top;    /**< Optional contact rectangle top offset. */
    int16_t contact_rect_right;  /**< Optional contact rectangle right offset. */
    int16_t contact_rect_bottom; /**< Optional contact rectangle bottom offset. */
    uint32_t orientation;        /**< Optional orientation value. */
    uint32_t pressure;           /**< Optional pressure value. */
} librdp_touch_contact;

/**
 * @brief Multi-touch frame supplied to librdp_session_send_touch_frame().
 *
 * contacts is borrowed for the duration of the send call and may be NULL only
 * when contact_count is 0.
 *
 * @since 0.1.0
 */
typedef struct librdp_touch_frame
{
    uint16_t contact_count;                  /**< Number of entries in contacts. */
    uint64_t frame_offset;                   /**< Frame timestamp offset in protocol units. */
    const librdp_touch_contact* contacts;    /**< Borrowed contact array. */
} librdp_touch_frame;

/**
 * @brief One pen contact in a pen input frame.
 *
 * Optional fields are valid only when their corresponding fields_present bit is
 * set. The structure is copied during the send call.
 *
 * @since 0.1.0
 */
typedef struct librdp_pen_contact
{
    uint8_t device_id;       /**< Local pen device identifier. */
    uint16_t fields_present; /**< Bitmask of LIBRDP_PEN_*_PRESENT values. */
    int32_t x;               /**< Pen x coordinate. */
    int32_t y;               /**< Pen y coordinate. */
    uint32_t contact_flags;  /**< Bitmask of LIBRDP_CONTACT_* values. */
    uint32_t pen_flags;      /**< Bitmask of LIBRDP_PEN_* state values. */
    uint32_t pressure;       /**< Optional pressure value. */
    uint16_t rotation;       /**< Optional rotation value. */
    int16_t tilt_x;          /**< Optional x-axis tilt. */
    int16_t tilt_y;          /**< Optional y-axis tilt. */
} librdp_pen_contact;

/**
 * @brief Pen input frame supplied to librdp_session_send_pen_frame().
 *
 * contacts is borrowed for the duration of the send call and may be NULL only
 * when contact_count is 0.
 *
 * @since 0.1.0
 */
typedef struct librdp_pen_frame
{
    uint16_t contact_count;               /**< Number of entries in contacts. */
    uint64_t frame_offset;                /**< Frame timestamp offset in protocol units. */
    const librdp_pen_contact* contacts;   /**< Borrowed pen contact array. */
} librdp_pen_frame;

#ifdef __cplusplus
}
#endif

#endif
