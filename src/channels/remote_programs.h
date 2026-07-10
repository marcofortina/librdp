#ifndef RDP_CHANNELS_REMOTE_PROGRAMS_H
#define RDP_CHANNELS_REMOTE_PROGRAMS_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_REMOTE_PROGRAMS_ORDER_EXEC 0x0001u
#define RDP_REMOTE_PROGRAMS_ORDER_ACTIVATE 0x0002u
#define RDP_REMOTE_PROGRAMS_ORDER_SYSPARAM 0x0003u
#define RDP_REMOTE_PROGRAMS_ORDER_SYSCOMMAND 0x0004u
#define RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE 0x0005u
#define RDP_REMOTE_PROGRAMS_ORDER_NOTIFY_EVENT 0x0006u
#define RDP_REMOTE_PROGRAMS_ORDER_WINDOWMOVE 0x0008u
#define RDP_REMOTE_PROGRAMS_ORDER_LOCALMOVESIZE 0x0009u
#define RDP_REMOTE_PROGRAMS_ORDER_MINMAXINFO 0x000au
#define RDP_REMOTE_PROGRAMS_ORDER_CLIENTSTATUS 0x000bu
#define RDP_REMOTE_PROGRAMS_ORDER_SYSMENU 0x000cu
#define RDP_REMOTE_PROGRAMS_ORDER_LANGBARINFO 0x000du
#define RDP_REMOTE_PROGRAMS_ORDER_GET_APPID_REQ 0x000eu
#define RDP_REMOTE_PROGRAMS_ORDER_GET_APPID_RESP 0x000fu
#define RDP_REMOTE_PROGRAMS_ORDER_TASKBARINFO 0x0010u
#define RDP_REMOTE_PROGRAMS_ORDER_LANGUAGEIMEINFO 0x0011u
#define RDP_REMOTE_PROGRAMS_ORDER_COMPARTMENTINFO 0x0012u
#define RDP_REMOTE_PROGRAMS_ORDER_HANDSHAKE_EX 0x0013u
#define RDP_REMOTE_PROGRAMS_ORDER_ZORDER_SYNC 0x0014u
#define RDP_REMOTE_PROGRAMS_ORDER_CLOAK 0x0015u
#define RDP_REMOTE_PROGRAMS_ORDER_POWER_DISPLAY_REQUEST 0x0016u
#define RDP_REMOTE_PROGRAMS_ORDER_SNAP_ARRANGE 0x0017u
#define RDP_REMOTE_PROGRAMS_ORDER_GET_APPID_RESP_EX 0x0018u
#define RDP_REMOTE_PROGRAMS_ORDER_TEXTSCALEINFO 0x0019u
#define RDP_REMOTE_PROGRAMS_ORDER_CARETBLINKINFO 0x001au
#define RDP_REMOTE_PROGRAMS_ORDER_EXEC_RESULT 0x0080u
#define RDP_REMOTE_PROGRAMS_EXEC_FLAG_EXPAND_WORKINGDIRECTORY 0x0001u
#define RDP_REMOTE_PROGRAMS_EXEC_FLAG_TRANSLATE_FILES 0x0002u
#define RDP_REMOTE_PROGRAMS_EXEC_FLAG_FILE 0x0004u
#define RDP_REMOTE_PROGRAMS_EXEC_FLAG_EXPAND_ARGUMENTS 0x0008u
#define RDP_REMOTE_PROGRAMS_EXEC_FLAG_APP_USER_MODEL_ID 0x0010u
#define RDP_REMOTE_PROGRAMS_EXEC_FLAG_KNOWN_MASK 0x001fu
#define RDP_REMOTE_PROGRAMS_EXEC_RESULT_OK 0x0000u
#define RDP_REMOTE_PROGRAMS_EXEC_RESULT_HOOK_NOT_LOADED 0x0001u
#define RDP_REMOTE_PROGRAMS_EXEC_RESULT_DECODE_FAILED 0x0002u
#define RDP_REMOTE_PROGRAMS_EXEC_RESULT_NOT_IN_ALLOWLIST 0x0003u
#define RDP_REMOTE_PROGRAMS_EXEC_RESULT_FILE_NOT_FOUND 0x0005u
#define RDP_REMOTE_PROGRAMS_EXEC_RESULT_FAIL 0x0006u
#define RDP_REMOTE_PROGRAMS_EXEC_RESULT_SESSION_LOCKED 0x0007u
#define RDP_REMOTE_PROGRAMS_CLIENTSTATUS_ALLOW_LOCAL_MOVE_SIZE 0x00000001u
#define RDP_REMOTE_PROGRAMS_CLIENTSTATUS_AUTORECONNECT 0x00000002u
#define RDP_REMOTE_PROGRAMS_CLIENTSTATUS_ZORDER_SYNC 0x00000004u
#define RDP_REMOTE_PROGRAMS_CLIENTSTATUS_RESIZE_MARGIN 0x00000010u
#define RDP_REMOTE_PROGRAMS_CLIENTSTATUS_HIGH_DPI_ICONS 0x00000020u
#define RDP_REMOTE_PROGRAMS_CLIENTSTATUS_APPBAR_REMOTING 0x00000040u
#define RDP_REMOTE_PROGRAMS_CLIENTSTATUS_POWER_DISPLAY_REQUEST 0x00000080u
#define RDP_REMOTE_PROGRAMS_CLIENTSTATUS_BIDIRECTIONAL_CLOAK 0x00000200u
#define RDP_REMOTE_PROGRAMS_CLIENTSTATUS_SUPPRESS_ICON_ORDERS 0x00000400u
#define RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_HIDEF 0x00000001u
#define RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_EXTENDED_SPI 0x00000002u
#define RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_SNAP_ARRANGE 0x00000004u
#define RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_TEXT_SCALE 0x00000008u
#define RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_CARET_BLINK 0x00000010u
#define RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_EXTENDED_SPI2 0x00000020u
#define RDP_REMOTE_PROGRAMS_HANDSHAKE_EX_EXTENDED_SPI3 0x00000040u
#define RDP_REMOTE_PROGRAMS_MAX_EXEC_PATH_BYTES 520u
#define RDP_REMOTE_PROGRAMS_MAX_ARGUMENT_BYTES 16000u
#define RDP_REMOTE_PROGRAMS_MAX_PDU_BYTES 65535u

typedef struct rdp_remote_programs_header
{
    uint16_t order_type;
    uint16_t order_length;
} rdp_remote_programs_header;

typedef struct rdp_remote_programs_u32_order
{
    rdp_remote_programs_header header;
    uint32_t value;
} rdp_remote_programs_u32_order;

typedef struct rdp_remote_programs_handshake_ex
{
    rdp_remote_programs_header header;
    uint32_t build_number;
    uint32_t flags;
} rdp_remote_programs_handshake_ex;

typedef struct rdp_remote_programs_exec
{
    rdp_remote_programs_header header;
    uint16_t flags;
    uint16_t exe_or_file_len;
    uint16_t working_dir_len;
    uint16_t arguments_len;
    const uint8_t* exe_or_file;
    const uint8_t* working_dir;
    const uint8_t* arguments;
} rdp_remote_programs_exec;

typedef struct rdp_remote_programs_exec_result
{
    rdp_remote_programs_header header;
    uint16_t flags;
    uint16_t exec_result;
    uint32_t raw_result;
    uint16_t exe_or_file_len;
    const uint8_t* exe_or_file;
} rdp_remote_programs_exec_result;

typedef struct rdp_remote_programs_activate
{
    rdp_remote_programs_header header;
    uint32_t window_id;
    uint8_t enabled;
} rdp_remote_programs_activate;

typedef struct rdp_remote_programs_sysmenu
{
    rdp_remote_programs_header header;
    uint32_t window_id;
    int16_t left;
    int16_t top;
} rdp_remote_programs_sysmenu;

typedef struct rdp_remote_programs_syscommand
{
    rdp_remote_programs_header header;
    uint32_t window_id;
    uint16_t command;
} rdp_remote_programs_syscommand;

typedef struct rdp_remote_programs_notify_event
{
    rdp_remote_programs_header header;
    uint32_t window_id;
    uint32_t notify_icon_id;
    uint32_t message;
} rdp_remote_programs_notify_event;

typedef struct rdp_remote_programs_minmaxinfo
{
    rdp_remote_programs_header header;
    uint32_t window_id;
    int16_t max_width;
    int16_t max_height;
    int16_t max_pos_x;
    int16_t max_pos_y;
    int16_t min_track_width;
    int16_t min_track_height;
    int16_t max_track_width;
    int16_t max_track_height;
} rdp_remote_programs_minmaxinfo;

typedef struct rdp_remote_programs_localmovesize
{
    rdp_remote_programs_header header;
    uint32_t window_id;
    uint16_t is_move_size_start;
    uint16_t move_size_type;
    int16_t pos_x;
    int16_t pos_y;
} rdp_remote_programs_localmovesize;

typedef struct rdp_remote_programs_windowmove
{
    rdp_remote_programs_header header;
    uint32_t window_id;
    int16_t left;
    int16_t top;
    int16_t right;
    int16_t bottom;
} rdp_remote_programs_windowmove;

typedef struct rdp_remote_programs_opaque
{
    rdp_remote_programs_header header;
    const uint8_t* payload;
    size_t payload_len;
} rdp_remote_programs_opaque;

int rdp_remote_programs_order_valid(uint16_t order_type);
int rdp_remote_programs_exec_flags_valid(uint16_t flags);
int rdp_remote_programs_exec_result_valid(uint16_t result);
librdp_status rdp_remote_programs_parse_header(const void* data,
                                               size_t length,
                                               rdp_remote_programs_header* header);
librdp_status rdp_remote_programs_write_header(rdp_buffer* buffer,
                                               uint16_t order_type,
                                               uint16_t order_length);
librdp_status rdp_remote_programs_parse_u32_order(const void* data,
                                                  size_t length,
                                                  uint16_t expected_order,
                                                  rdp_remote_programs_u32_order* order);
librdp_status rdp_remote_programs_write_u32_order(rdp_buffer* buffer,
                                                  uint16_t order_type,
                                                  uint32_t value);
librdp_status rdp_remote_programs_parse_handshake_ex(const void* data,
                                                     size_t length,
                                                     rdp_remote_programs_handshake_ex* order);
librdp_status rdp_remote_programs_write_handshake_ex(rdp_buffer* buffer,
                                                     uint32_t build_number,
                                                     uint32_t flags);
librdp_status rdp_remote_programs_parse_exec(const void* data,
                                             size_t length,
                                             rdp_remote_programs_exec* order);
librdp_status rdp_remote_programs_write_exec(rdp_buffer* buffer,
                                             uint16_t flags,
                                             const void* exe_or_file,
                                             uint16_t exe_or_file_len,
                                             const void* working_dir,
                                             uint16_t working_dir_len,
                                             const void* arguments,
                                             uint16_t arguments_len);
librdp_status rdp_remote_programs_parse_exec_result(const void* data,
                                                    size_t length,
                                                    rdp_remote_programs_exec_result* order);
librdp_status rdp_remote_programs_write_exec_result(rdp_buffer* buffer,
                                                    uint16_t flags,
                                                    uint16_t exec_result,
                                                    uint32_t raw_result,
                                                    const void* exe_or_file,
                                                    uint16_t exe_or_file_len);
librdp_status rdp_remote_programs_parse_activate(const void* data,
                                                 size_t length,
                                                 rdp_remote_programs_activate* order);
librdp_status rdp_remote_programs_write_activate(rdp_buffer* buffer,
                                                 uint32_t window_id,
                                                 uint8_t enabled);
librdp_status rdp_remote_programs_parse_sysmenu(const void* data,
                                                size_t length,
                                                rdp_remote_programs_sysmenu* order);
librdp_status rdp_remote_programs_write_sysmenu(rdp_buffer* buffer,
                                                uint32_t window_id,
                                                int16_t left,
                                                int16_t top);
librdp_status rdp_remote_programs_parse_syscommand(const void* data,
                                                   size_t length,
                                                   rdp_remote_programs_syscommand* order);
librdp_status rdp_remote_programs_write_syscommand(rdp_buffer* buffer,
                                                   uint32_t window_id,
                                                   uint16_t command);
librdp_status rdp_remote_programs_parse_notify_event(const void* data,
                                                     size_t length,
                                                     rdp_remote_programs_notify_event* order);
librdp_status rdp_remote_programs_write_notify_event(rdp_buffer* buffer,
                                                     uint32_t window_id,
                                                     uint32_t notify_icon_id,
                                                     uint32_t message);
librdp_status rdp_remote_programs_parse_minmaxinfo(const void* data,
                                                   size_t length,
                                                   rdp_remote_programs_minmaxinfo* order);
librdp_status rdp_remote_programs_write_minmaxinfo(rdp_buffer* buffer,
                                                   const rdp_remote_programs_minmaxinfo* order);
librdp_status rdp_remote_programs_parse_localmovesize(const void* data,
                                                      size_t length,
                                                      rdp_remote_programs_localmovesize* order);
librdp_status rdp_remote_programs_write_localmovesize(rdp_buffer* buffer,
                                                      const rdp_remote_programs_localmovesize* order);
librdp_status rdp_remote_programs_parse_windowmove(const void* data,
                                                   size_t length,
                                                   rdp_remote_programs_windowmove* order);
librdp_status rdp_remote_programs_write_windowmove(rdp_buffer* buffer,
                                                   uint32_t window_id,
                                                   int16_t left,
                                                   int16_t top,
                                                   int16_t right,
                                                   int16_t bottom);
librdp_status rdp_remote_programs_parse_opaque(const void* data,
                                               size_t length,
                                               rdp_remote_programs_opaque* order);
librdp_status rdp_remote_programs_write_opaque(rdp_buffer* buffer,
                                               uint16_t order_type,
                                               const void* payload,
                                               size_t payload_len);

#endif
