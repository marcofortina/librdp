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
#define RDP_SMARTCARD_REDIRECTION_DEVICE_CONTROL_REQUEST_LENGTH 32u
#define RDP_SMARTCARD_REDIRECTION_SCOPE_USER 0x00000000u
#define RDP_SMARTCARD_REDIRECTION_SCOPE_TERMINAL 0x00000001u
#define RDP_SMARTCARD_REDIRECTION_SCOPE_SYSTEM 0x00000002u

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

typedef struct rdp_smartcard_redirection_establish_context_call
{
    uint32_t scope;
} rdp_smartcard_redirection_establish_context_call;

typedef struct rdp_smartcard_redirection_long_return
{
    uint32_t return_code;
} rdp_smartcard_redirection_long_return;

int rdp_smartcard_redirection_ioctl_valid(uint32_t io_control_code);
librdp_status rdp_smartcard_redirection_parse_device_control_request(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_device_control_request* request);
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
librdp_status rdp_smartcard_redirection_parse_long_return(
    const void* data,
    size_t length,
    rdp_smartcard_redirection_long_return* result);
librdp_status rdp_smartcard_redirection_write_long_return(
    rdp_buffer* buffer,
    uint32_t return_code);

#endif
