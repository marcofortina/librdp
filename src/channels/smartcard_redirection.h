#ifndef RDP_CHANNELS_SMARTCARD_REDIRECTION_H
#define RDP_CHANNELS_SMARTCARD_REDIRECTION_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#include "common/buffer.h"

#define RDP_SMARTCARD_REDIRECTION_IOCTL_ESTABLISHCONTEXT 0x00090014u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_RELEASECONTEXT 0x00090018u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_ISVALIDCONTEXT 0x0009001cu
#define RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERGROUPSA 0x00090020u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERGROUPSW 0x00090024u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERSA 0x00090028u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_LISTREADERSW 0x0009002cu
#define RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERGROUPA 0x00090050u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERGROUPW 0x00090054u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERGROUPA 0x00090058u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERGROUPW 0x0009005cu
#define RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERA 0x00090060u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_INTRODUCEREADERW 0x00090064u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERA 0x00090068u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_FORGETREADERW 0x0009006cu
#define RDP_SMARTCARD_REDIRECTION_IOCTL_ADDREADERTOGROUPA 0x00090070u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_ADDREADERTOGROUPW 0x00090074u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_REMOVEREADERFROMGROUPA 0x00090078u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_REMOVEREADERFROMGROUPW 0x0009007cu
#define RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSA 0x00090098u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSW 0x0009009cu
#define RDP_SMARTCARD_REDIRECTION_IOCTL_GETSTATUSCHANGEA 0x000900a0u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_GETSTATUSCHANGEW 0x000900a4u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_CANCEL 0x000900a8u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_CONNECTA 0x000900acu
#define RDP_SMARTCARD_REDIRECTION_IOCTL_CONNECTW 0x000900b0u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_RECONNECT 0x000900b4u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_DISCONNECT 0x000900b8u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_BEGINTRANSACTION 0x000900bcu
#define RDP_SMARTCARD_REDIRECTION_IOCTL_ENDTRANSACTION 0x000900c0u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_STATE 0x000900c4u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_STATUSA 0x000900c8u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_STATUSW 0x000900ccu
#define RDP_SMARTCARD_REDIRECTION_IOCTL_TRANSMIT 0x000900d0u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_CONTROL 0x000900d4u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_GETATTRIB 0x000900d8u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_SETATTRIB 0x000900dcu
#define RDP_SMARTCARD_REDIRECTION_IOCTL_ACCESSSTARTEDEVENT 0x000900e0u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSBYATRA 0x000900e8u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_LOCATECARDSBYATRW 0x000900ecu
#define RDP_SMARTCARD_REDIRECTION_IOCTL_READCACHEA 0x000900f0u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_READCACHEW 0x000900f4u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_WRITECACHEA 0x000900f8u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_WRITECACHEW 0x000900fcu
#define RDP_SMARTCARD_REDIRECTION_IOCTL_GETTRANSMITCOUNT 0x00090100u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_GETREADERICON 0x00090104u
#define RDP_SMARTCARD_REDIRECTION_IOCTL_GETDEVICETYPEID 0x00090108u

#define RDP_SMARTCARD_REDIRECTION_CONTEXT_MAX_LENGTH 16u
#define RDP_SMARTCARD_REDIRECTION_IO_REQUEST_MAX_EXTRA 1024u
#define RDP_SMARTCARD_REDIRECTION_BUFFER_MAX_LENGTH 4194304u
#define RDP_SMARTCARD_REDIRECTION_DEVICE_CONTROL_REQUEST_LENGTH 32u
#define RDP_SMARTCARD_REDIRECTION_MESSAGE_RAW 0u
#define RDP_SMARTCARD_REDIRECTION_MESSAGE_CONTEXT 1u
#define RDP_SMARTCARD_REDIRECTION_MESSAGE_ESTABLISH_CONTEXT 2u
#define RDP_SMARTCARD_REDIRECTION_MESSAGE_HANDLE 3u
#define RDP_SMARTCARD_REDIRECTION_MESSAGE_HANDLE_DISPOSITION 4u
#define RDP_SMARTCARD_REDIRECTION_MESSAGE_RECONNECT 5u
#define RDP_SMARTCARD_REDIRECTION_MESSAGE_STATE 6u
#define RDP_SMARTCARD_REDIRECTION_MESSAGE_STATUS 7u
#define RDP_SMARTCARD_REDIRECTION_MESSAGE_TRANSMIT 8u
#define RDP_SMARTCARD_REDIRECTION_MESSAGE_CONTROL 9u
#define RDP_SMARTCARD_REDIRECTION_MESSAGE_ATTRIB 10u
#define RDP_SMARTCARD_REDIRECTION_MESSAGE_SET_ATTRIB 11u
#define RDP_SMARTCARD_REDIRECTION_SCOPE_USER 0x00000000u
#define RDP_SMARTCARD_REDIRECTION_SCOPE_TERMINAL 0x00000001u
#define RDP_SMARTCARD_REDIRECTION_SCOPE_SYSTEM 0x00000002u
#define RDP_SMARTCARD_REDIRECTION_PROTOCOL_UNDEFINED 0x00000000u
#define RDP_SMARTCARD_REDIRECTION_PROTOCOL_T0 0x00000001u
#define RDP_SMARTCARD_REDIRECTION_PROTOCOL_T1 0x00000002u
#define RDP_SMARTCARD_REDIRECTION_PROTOCOL_TX 0x00000003u
#define RDP_SMARTCARD_REDIRECTION_PROTOCOL_RAW 0x00010000u
#define RDP_SMARTCARD_REDIRECTION_PROTOCOL_DEFAULT 0x80000000u
#define RDP_SMARTCARD_REDIRECTION_SHARE_EXCLUSIVE 0x00000001u
#define RDP_SMARTCARD_REDIRECTION_SHARE_SHARED 0x00000002u
#define RDP_SMARTCARD_REDIRECTION_SHARE_DIRECT 0x00000003u
#define RDP_SMARTCARD_REDIRECTION_LEAVE_CARD 0x00000000u
#define RDP_SMARTCARD_REDIRECTION_RESET_CARD 0x00000001u
#define RDP_SMARTCARD_REDIRECTION_UNPOWER_CARD 0x00000002u
#define RDP_SMARTCARD_REDIRECTION_EJECT_CARD 0x00000003u
#define RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH 36u
#define RDP_SMARTCARD_REDIRECTION_TRANSMIT_MAX_LENGTH 66560u
#define RDP_SMARTCARD_REDIRECTION_ATTRIB_MAX_LENGTH 65536u

typedef struct rdp_smartcard_redirection_device_control_request
{
    uint32_t output_buffer_len;
    uint32_t input_buffer_len;
    uint32_t io_control_code;
    const uint8_t* input;
    size_t input_len;
} rdp_smartcard_redirection_device_control_request;

typedef struct rdp_smartcard_redirection_device_control_response
{
    uint32_t output_buffer_len;
    const uint8_t* output;
    size_t output_len;
} rdp_smartcard_redirection_device_control_response;

typedef struct rdp_smartcard_redirection_context
{
    uint32_t length;
    const uint8_t* data;
} rdp_smartcard_redirection_context;

typedef struct rdp_smartcard_redirection_handle
{
    rdp_smartcard_redirection_context context;
    uint32_t length;
    const uint8_t* data;
} rdp_smartcard_redirection_handle;

typedef struct rdp_smartcard_redirection_scard_io_request
{
    uint32_t protocol;
    uint32_t extra_bytes_len;
    const uint8_t* extra_bytes;
} rdp_smartcard_redirection_scard_io_request;

typedef struct rdp_smartcard_redirection_atr_mask
{
    uint32_t atr_len;
    uint8_t atr[RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH];
    uint8_t mask[RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH];
} rdp_smartcard_redirection_atr_mask;

typedef struct rdp_smartcard_redirection_reader_state_common
{
    uint32_t current_state;
    uint32_t event_state;
    uint32_t atr_len;
    uint8_t atr[RDP_SMARTCARD_REDIRECTION_ATR_MAX_LENGTH];
} rdp_smartcard_redirection_reader_state_common;

typedef struct rdp_smartcard_redirection_establish_context_call
{
    uint32_t scope;
} rdp_smartcard_redirection_establish_context_call;

typedef struct rdp_smartcard_redirection_connect_common
{
    rdp_smartcard_redirection_context context;
    uint32_t share_mode;
    uint32_t preferred_protocols;
} rdp_smartcard_redirection_connect_common;

typedef struct rdp_smartcard_redirection_reconnect_call
{
    rdp_smartcard_redirection_handle handle;
    uint32_t share_mode;
    uint32_t preferred_protocols;
    uint32_t initialization;
} rdp_smartcard_redirection_reconnect_call;

typedef struct rdp_smartcard_redirection_handle_disposition_call
{
    rdp_smartcard_redirection_handle handle;
    uint32_t disposition;
} rdp_smartcard_redirection_handle_disposition_call;

typedef struct rdp_smartcard_redirection_state_call
{
    rdp_smartcard_redirection_handle handle;
    uint32_t atr_is_null;
    uint32_t atr_len;
} rdp_smartcard_redirection_state_call;

typedef struct rdp_smartcard_redirection_status_call
{
    rdp_smartcard_redirection_handle handle;
    uint32_t reader_names_is_null;
    uint32_t reader_len;
    uint32_t atr_len;
} rdp_smartcard_redirection_status_call;

typedef struct rdp_smartcard_redirection_transmit_call
{
    rdp_smartcard_redirection_handle handle;
    rdp_smartcard_redirection_scard_io_request send_pci;
    uint32_t send_len;
    const uint8_t* send_data;
    uint32_t recv_pci_present;
    rdp_smartcard_redirection_scard_io_request recv_pci;
    uint32_t recv_buffer_is_null;
    uint32_t recv_len;
} rdp_smartcard_redirection_transmit_call;

typedef struct rdp_smartcard_redirection_control_call
{
    rdp_smartcard_redirection_handle handle;
    uint32_t control_code;
    uint32_t input_len;
    const uint8_t* input;
    uint32_t output_buffer_is_null;
    uint32_t output_len;
} rdp_smartcard_redirection_control_call;

typedef struct rdp_smartcard_redirection_attrib_call
{
    rdp_smartcard_redirection_handle handle;
    uint32_t attr_id;
    uint32_t attr_is_null;
    uint32_t attr_len;
} rdp_smartcard_redirection_attrib_call;

typedef struct rdp_smartcard_redirection_set_attrib_call
{
    rdp_smartcard_redirection_handle handle;
    uint32_t attr_id;
    uint32_t attr_len;
    const uint8_t* attr;
} rdp_smartcard_redirection_set_attrib_call;

typedef struct rdp_smartcard_redirection_long_return
{
    uint32_t return_code;
} rdp_smartcard_redirection_long_return;

typedef struct rdp_smartcard_redirection_count_return
{
    uint32_t return_code;
    uint32_t value;
} rdp_smartcard_redirection_count_return;

typedef struct rdp_smartcard_redirection_buffer_return
{
    uint32_t return_code;
    uint32_t data_len;
    const uint8_t* data;
} rdp_smartcard_redirection_buffer_return;

typedef struct rdp_smartcard_redirection_establish_context_return
{
    uint32_t return_code;
    rdp_smartcard_redirection_context context;
} rdp_smartcard_redirection_establish_context_return;

typedef struct rdp_smartcard_redirection_connect_return
{
    uint32_t return_code;
    rdp_smartcard_redirection_handle handle;
    uint32_t active_protocol;
} rdp_smartcard_redirection_connect_return;

typedef struct rdp_smartcard_redirection_status_return
{
    uint32_t return_code;
    uint32_t reader_names_len;
    const uint8_t* reader_names;
    uint32_t state;
    uint32_t protocol;
    uint32_t atr_len;
    const uint8_t* atr;
} rdp_smartcard_redirection_status_return;

typedef struct rdp_smartcard_redirection_transmit_return
{
    uint32_t return_code;
    uint32_t recv_protocol;
    const uint8_t* recv_extra;
    uint32_t recv_extra_len;
    const uint8_t* recv_data;
    uint32_t recv_data_len;
} rdp_smartcard_redirection_transmit_return;

typedef struct rdp_smartcard_redirection_request_message
{
    rdp_smartcard_redirection_device_control_request request;
    uint32_t kind;
    union
    {
        rdp_smartcard_redirection_context context;
        rdp_smartcard_redirection_establish_context_call establish_context;
        rdp_smartcard_redirection_handle handle;
        rdp_smartcard_redirection_handle_disposition_call handle_disposition;
        rdp_smartcard_redirection_reconnect_call reconnect;
        rdp_smartcard_redirection_state_call state;
        rdp_smartcard_redirection_status_call status;
        rdp_smartcard_redirection_transmit_call transmit;
        rdp_smartcard_redirection_control_call control;
        rdp_smartcard_redirection_attrib_call attrib;
        rdp_smartcard_redirection_set_attrib_call set_attrib;
    } body;
} rdp_smartcard_redirection_request_message;

int rdp_smartcard_redirection_ioctl_valid(uint32_t io_control_code);
int rdp_smartcard_redirection_share_mode_valid(uint32_t share_mode);
int rdp_smartcard_redirection_protocol_mask_valid(uint32_t protocols);
int rdp_smartcard_redirection_bool_valid(uint32_t value);
int rdp_smartcard_redirection_disposition_valid(uint32_t disposition);
int rdp_smartcard_redirection_initialization_valid(uint32_t initialization);
librdp_status rdp_smartcard_redirection_parse_atr_mask(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_atr_mask* mask);
librdp_status rdp_smartcard_redirection_write_atr_mask(
    rdp_buffer* buffer,
    const uint8_t* atr,
    uint32_t atr_len,
    const uint8_t* mask);
librdp_status rdp_smartcard_redirection_parse_reader_state_common(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_reader_state_common* state);
librdp_status rdp_smartcard_redirection_write_reader_state_common(
    rdp_buffer* buffer,
    uint32_t current_state,
    uint32_t event_state,
    const uint8_t* atr,
    uint32_t atr_len);
librdp_status rdp_smartcard_redirection_parse_device_control_request(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_device_control_request* request);
librdp_status rdp_smartcard_redirection_parse_device_control_request_message(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_request_message* message);
librdp_status rdp_smartcard_redirection_write_device_control_request(
    rdp_buffer* buffer,
    uint32_t output_buffer_len,
    uint32_t io_control_code,
    const void* input,
    uint32_t input_len);
librdp_status rdp_smartcard_redirection_parse_device_control_response(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_device_control_response* response);
librdp_status rdp_smartcard_redirection_write_device_control_response(
    rdp_buffer* buffer,
    const void* output,
    uint32_t output_len);
librdp_status rdp_smartcard_redirection_parse_establish_context_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_establish_context_call* call);
librdp_status rdp_smartcard_redirection_write_establish_context_call(
    rdp_buffer* buffer,
    uint32_t scope);
librdp_status rdp_smartcard_redirection_parse_context(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_context* context);
librdp_status rdp_smartcard_redirection_write_context(
    rdp_buffer* buffer,
    const void* data,
    uint32_t length);
librdp_status rdp_smartcard_redirection_parse_handle(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_handle* handle);
librdp_status rdp_smartcard_redirection_write_handle(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len);
librdp_status rdp_smartcard_redirection_parse_scard_io_request(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_scard_io_request* request);
librdp_status rdp_smartcard_redirection_write_scard_io_request(
    rdp_buffer* buffer,
    uint32_t protocol,
    const void* extra_bytes,
    uint32_t extra_bytes_len);
librdp_status rdp_smartcard_redirection_parse_connect_common(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_connect_common* common);
librdp_status rdp_smartcard_redirection_write_connect_common(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    uint32_t share_mode,
    uint32_t preferred_protocols);
librdp_status rdp_smartcard_redirection_parse_reconnect_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_reconnect_call* call);
librdp_status rdp_smartcard_redirection_write_reconnect_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t share_mode,
    uint32_t preferred_protocols,
    uint32_t initialization);
librdp_status rdp_smartcard_redirection_parse_handle_disposition_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_handle_disposition_call* call);
librdp_status rdp_smartcard_redirection_write_handle_disposition_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t disposition);
librdp_status rdp_smartcard_redirection_parse_state_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_state_call* call);
librdp_status rdp_smartcard_redirection_write_state_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t atr_is_null,
    uint32_t atr_len);
librdp_status rdp_smartcard_redirection_parse_status_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_status_call* call);
librdp_status rdp_smartcard_redirection_write_status_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t reader_names_is_null,
    uint32_t reader_len,
    uint32_t atr_len);
librdp_status rdp_smartcard_redirection_parse_transmit_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_transmit_call* call);
librdp_status rdp_smartcard_redirection_write_transmit_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t send_protocol,
    const void* send_extra,
    uint32_t send_extra_len,
    const void* send_data,
    uint32_t send_len,
    uint32_t recv_pci_present,
    uint32_t recv_protocol,
    const void* recv_extra,
    uint32_t recv_extra_len,
    uint32_t recv_buffer_is_null,
    uint32_t recv_len);
librdp_status rdp_smartcard_redirection_parse_control_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_control_call* call);
librdp_status rdp_smartcard_redirection_write_control_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t control_code,
    const void* input,
    uint32_t input_len,
    uint32_t output_buffer_is_null,
    uint32_t output_len);
librdp_status rdp_smartcard_redirection_parse_attrib_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_attrib_call* call);
librdp_status rdp_smartcard_redirection_write_attrib_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t attr_id,
    uint32_t attr_is_null,
    uint32_t attr_len);
librdp_status rdp_smartcard_redirection_parse_set_attrib_call(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_set_attrib_call* call);
librdp_status rdp_smartcard_redirection_write_set_attrib_call(
    rdp_buffer* buffer,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t attr_id,
    const void* attr,
    uint32_t attr_len);
librdp_status rdp_smartcard_redirection_parse_long_return(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_long_return* result);
librdp_status rdp_smartcard_redirection_write_long_return(
    rdp_buffer* buffer,
    uint32_t return_code);
librdp_status rdp_smartcard_redirection_parse_count_return(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_count_return* result);
librdp_status rdp_smartcard_redirection_write_count_return(
    rdp_buffer* buffer,
    uint32_t return_code,
    uint32_t value);
librdp_status rdp_smartcard_redirection_parse_buffer_return(
    const void* data,
    size_t length,
    uint32_t max_data_len,
    rdp_smartcard_redirection_buffer_return* result);
librdp_status rdp_smartcard_redirection_write_buffer_return(
    rdp_buffer* buffer,
    uint32_t return_code,
    const void* data,
    uint32_t data_len);
librdp_status rdp_smartcard_redirection_write_establish_context_return(
    rdp_buffer* buffer,
    uint32_t return_code,
    const void* context,
    uint32_t context_len);
librdp_status rdp_smartcard_redirection_parse_establish_context_return(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_establish_context_return* result);
librdp_status rdp_smartcard_redirection_write_connect_return(
    rdp_buffer* buffer,
    uint32_t return_code,
    const void* context,
    uint32_t context_len,
    const void* handle,
    uint32_t handle_len,
    uint32_t active_protocol);
librdp_status rdp_smartcard_redirection_parse_connect_return(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_connect_return* result);
librdp_status rdp_smartcard_redirection_write_reconnect_return(
    rdp_buffer* buffer,
    uint32_t return_code,
    uint32_t active_protocol);
librdp_status rdp_smartcard_redirection_write_status_return(
    rdp_buffer* buffer,
    uint32_t return_code,
    const void* reader_names,
    uint32_t reader_names_len,
    uint32_t state,
    uint32_t protocol,
    const void* atr,
    uint32_t atr_len);
librdp_status rdp_smartcard_redirection_parse_status_return(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_status_return* result);
librdp_status rdp_smartcard_redirection_write_transmit_return(
    rdp_buffer* buffer,
    uint32_t return_code,
    uint32_t recv_protocol,
    const void* recv_extra,
    uint32_t recv_extra_len,
    const void* recv_data,
    uint32_t recv_data_len);
librdp_status rdp_smartcard_redirection_parse_transmit_return(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_transmit_return* result);

#endif
