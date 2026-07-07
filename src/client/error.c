#include <librdp/error.h>

const char* librdp_status_string(librdp_status status)
{
    switch (status)
    {
        case LIBRDP_STATUS_OK:
            return "ok";
        case LIBRDP_STATUS_INVALID_ARGUMENT:
            return "invalid_argument";
        case LIBRDP_STATUS_NO_MEMORY:
            return "no_memory";
        case LIBRDP_STATUS_IO_ERROR:
            return "io_error";
        case LIBRDP_STATUS_PROTOCOL_ERROR:
            return "protocol_error";
        case LIBRDP_STATUS_UNSUPPORTED:
            return "unsupported";
        case LIBRDP_STATUS_TIMEOUT:
            return "timeout";
        case LIBRDP_STATUS_CLOSED:
            return "closed";
        case LIBRDP_STATUS_AGAIN:
            return "again";
        case LIBRDP_STATUS_STATE:
            return "state";
        default:
            return "unknown";
    }
}
