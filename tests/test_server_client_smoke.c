/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: application desktop-server loopback smoke tests.
 * Coverage: Standard, TLS, and NLA activation through the shared server host
 * with synthetic capture, input, clipboard, drive, and permission providers.
 * Bug classes: security-profile drift, provider negotiation gaps, stalled
 * activation, missing graphics delivery, dropped input, and drive lifecycle.
 * Determinism: all transport stays on loopback, credentials and certificates
 * are ephemeral, and native providers use bounded in-memory state.
 */

#include "client_runtime.h"
#include "client/session_internal.h"
#include "client/session_redirection.h"
#include "server_host.h"
#include "server_platform.h"
#include "test_http_proxy.h"
#include "test_process_state.h"
#include "test_rdg_gateway.h"
#include "test_server_client_clipboard.h"
#include "test_server_support.h"

#include "channels/graphics_pipeline.h"
#include "channels/filesystem_redirection.h"
#include "graphics/bitmap.h"
#include "graphics/planar.h"
#include "graphics/rfx_codec.h"
#include "graphics/surface_commands.h"
#include "protocol/fastpath.h"
#include "protocol/session_selection.h"
#include "server/server_internal.h"
#include "server/server_security.h"

#include <librdp/librdp.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#if defined(RDP_HAVE_ATTR) && defined(__linux__)
#include <sys/xattr.h>
#endif
#include <time.h>
#include <unistd.h>

#define SMOKE_WIDTH LIBRDP_DESKTOP_MIN_DIMENSION
#define SMOKE_HEIGHT LIBRDP_DESKTOP_MIN_DIMENSION
#define SMOKE_CAPTURE_WIDTH LIBRDP_DESKTOP_MIN_DIMENSION
#define SMOKE_CAPTURE_HEIGHT LIBRDP_DESKTOP_MIN_DIMENSION
#define SMOKE_PIXEL_BYTES (SMOKE_CAPTURE_WIDTH * SMOKE_CAPTURE_HEIGHT * 4u)
#define SMOKE_PUMP_LIMIT 500u
#define SMOKE_LIFECYCLE_CAPACITY 32u
#define SMOKE_TRACE_RECENT_CAPACITY 32u
#define SMOKE_TRACE_RECENT_LINE 256u
#define SMOKE_LIFECYCLE_STRESS_CYCLES 24u
#define SMOKE_LIFECYCLE_STRESS_WARMUP_CYCLES 4u
#define SMOKE_LIFECYCLE_STRESS_RSS_ALLOWANCE (32u * 1024u * 1024u)
#define SMOKE_DESCRIPTOR_SCAN_LIMIT 1048576L
#define SMOKE_SHA256_BYTES 32u
#define SMOKE_AUTH_REDIRECTION_CHANNEL_ID 0x4155u
#define SMOKE_DRIVE_GENERIC_READ 0x80000000u
#define SMOKE_DRIVE_GENERIC_WRITE 0x40000000u
#define SMOKE_DRIVE_SHARE_ALL 0x00000007u
#define SMOKE_DRIVE_OPEN_EXISTING 1u
#define SMOKE_DRIVE_CREATE_NEW 2u
#define SMOKE_DRIVE_DIRECTORY_OPTION 0x00000001u
#define SMOKE_DRIVE_FILE_RENAME_INFORMATION 10u
#define SMOKE_DRIVE_FILE_DISPOSITION_INFORMATION 13u
#define SMOKE_DRIVE_FILE_END_OF_FILE_INFORMATION 20u
#define SMOKE_DRIVE_LARGE_OFFSET UINT64_C(5368709120)
#define SMOKE_DRIVE_ACCESS_FILETIME UINT64_C(133000000000000000)
#define SMOKE_DRIVE_WRITE_FILETIME UINT64_C(133000000100000000)
#define SMOKE_DRIVE_METADATA_MODE 0640u
#define SMOKE_DRIVE_METADATA_XATTR "user.librdp.smoke"
#define SMOKE_DRIVE_DOS_ATTRIBUTES_XATTR "user.DOSATTRIB"

#if defined(__SANITIZE_ADDRESS__)
#define SMOKE_ADDRESS_SANITIZER_ACTIVE 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define SMOKE_ADDRESS_SANITIZER_ACTIVE 1
#else
#define SMOKE_ADDRESS_SANITIZER_ACTIVE 0
#endif
#else
#define SMOKE_ADDRESS_SANITIZER_ACTIVE 0
#endif

typedef struct smoke_nla_identity
{
    const char* username;
    const char* password;
    const char* domain;
} smoke_nla_identity;

static const smoke_nla_identity smoke_nla_default_identity = {
    "smoke-user-731",
    "smoke-secret-739",
    "SMOKE-DOMAIN-733",
};
static const smoke_nla_identity smoke_nla_no_domain_identity = {
    "smoke-user-743",
    "smoke-secret-751",
    NULL,
};
static const smoke_nla_identity smoke_nla_empty_domain_identity = {
    "smoke-user-757",
    "smoke-secret-761",
    "",
};
static const smoke_nla_identity smoke_nla_upn_identity = {
    "smoke.user.769@example.test",
    "smoke-secret-773",
    NULL,
};
static const smoke_nla_identity smoke_nla_utf8_identity = {
    "smoke-us\xc3\xa9r-787",
    "smoke-secret-797",
    "D\xc3\x96M\xc3\x84IN-809",
};
static const smoke_nla_identity smoke_nla_unknown_user_identity = {
    "unknown-smoke-user-853",
    "smoke-secret-857",
    "SMOKE-DOMAIN-733",
};
static const smoke_nla_identity smoke_nla_wrong_domain_identity = {
    "smoke-user-731",
    "smoke-secret-859",
    "UNTRUSTED-DOMAIN-863",
};
static const smoke_nla_identity smoke_gateway_identity = {
    "gateway-user-811",
    "gateway-secret-821",
    "GATEWAY-DOMAIN-823",
};
static const smoke_nla_identity smoke_gateway_reject_identity = {
    "gateway-reject-user-827",
    "gateway-reject-secret-829",
    "GATEWAY-REJECT-DOMAIN-839",
};
static const uint8_t smoke_frame_sha256[SMOKE_SHA256_BYTES] = {
    0x91, 0x43, 0x12, 0xa9, 0x79, 0x81, 0xea, 0x05,
    0x7b, 0xc0, 0x70, 0x89, 0xd2, 0x35, 0x85, 0x90,
    0xa7, 0x9d, 0x05, 0xcc, 0x05, 0xb9, 0x07, 0x3d,
    0x7a, 0x63, 0x59, 0x09, 0xb9, 0xfc, 0x7b, 0xec,
};
static const uint8_t smoke_alternate_frame_sha256[SMOKE_SHA256_BYTES] = {
    0xac, 0x72, 0x02, 0xe7, 0xf6, 0x7f, 0x6a, 0x48,
    0x98, 0x87, 0xb6, 0xca, 0x2e, 0x2e, 0x55, 0x19,
    0x40, 0x42, 0xc0, 0x0e, 0x14, 0xe6, 0xa9, 0x77,
    0x96, 0x55, 0x26, 0xbc, 0x9e, 0x7f, 0xfd, 0xf5,
};
static const uint8_t smoke_fastpath_bitmap_sha256[SMOKE_SHA256_BYTES] = {
    0xbe, 0x9b, 0x92, 0xcb, 0xbe, 0xa1, 0xde, 0x7b,
    0xac, 0xb2, 0x82, 0x48, 0xc0, 0x1d, 0x22, 0xa1,
    0x66, 0xbe, 0x42, 0x44, 0x59, 0xd9, 0x83, 0xc5,
    0x82, 0x6a, 0x54, 0x7c, 0x8f, 0x9d, 0xed, 0x98,
};

typedef enum smoke_drive_mode
{
    SMOKE_DRIVE_NONE = 0,
    SMOKE_DRIVE_READ_ONLY = 1,
    SMOKE_DRIVE_WRITABLE = 2,
    SMOKE_DRIVE_INFORMATION = 3,
    SMOKE_DRIVE_ENUMERATION = 4,
    SMOKE_DRIVE_LOCKING = 5,
    SMOKE_DRIVE_NOTIFY = 6,
    SMOKE_DRIVE_METADATA = 7,
    SMOKE_DRIVE_CONFINEMENT = 8,
    SMOKE_DRIVE_DEVICE_NODE = 9,
    SMOKE_DRIVE_LIMITS = 10
} smoke_drive_mode;

typedef enum smoke_drive_stage
{
    SMOKE_DRIVE_STAGE_DISABLED = 0,
    SMOKE_DRIVE_STAGE_WAIT_VOLUME = 1,
    SMOKE_DRIVE_STAGE_OPEN_FILE = 2,
    SMOKE_DRIVE_STAGE_READ_FILE = 3,
    SMOKE_DRIVE_STAGE_QUERY_FILE = 4,
    SMOKE_DRIVE_STAGE_OPEN_DIRECTORY = 5,
    SMOKE_DRIVE_STAGE_QUERY_DIRECTORY = 6,
    SMOKE_DRIVE_STAGE_WRITE_DENIED = 7,
    SMOKE_DRIVE_STAGE_RENAME_DENIED = 8,
    SMOKE_DRIVE_STAGE_DELETE_DENIED = 9,
    SMOKE_DRIVE_STAGE_WRITE_FILE = 10,
    SMOKE_DRIVE_STAGE_APPEND_FILE = 11,
    SMOKE_DRIVE_STAGE_FLUSH_FILE = 12,
    SMOKE_DRIVE_STAGE_TRUNCATE_FILE = 13,
    SMOKE_DRIVE_STAGE_READ_TRUNCATED = 14,
    SMOKE_DRIVE_STAGE_RENAME_FILE = 15,
    SMOKE_DRIVE_STAGE_DELETE_FILE = 16,
    SMOKE_DRIVE_STAGE_CLEANUP_FILE = 17,
    SMOKE_DRIVE_STAGE_CLOSE_FILE = 18,
    SMOKE_DRIVE_STAGE_CLOSE_DIRECTORY = 19,
    SMOKE_DRIVE_STAGE_QUERY_FILE_CLASSES = 20,
    SMOKE_DRIVE_STAGE_QUERY_VOLUME_CLASSES = 21,
    SMOKE_DRIVE_STAGE_QUERY_SECURITY_CLASSES = 22,
    SMOKE_DRIVE_STAGE_OPEN_INFORMATION_DIRECTORY = 23,
    SMOKE_DRIVE_STAGE_QUERY_DIRECTORY_CLASSES = 24,
    SMOKE_DRIVE_STAGE_CLOSE_INFORMATION_DIRECTORY = 25,
    SMOKE_DRIVE_STAGE_CLOSE_INFORMATION_FILE = 26,
    SMOKE_DRIVE_STAGE_OPEN_ENUMERATION_DIRECTORY = 27,
    SMOKE_DRIVE_STAGE_QUERY_ENUMERATION_MATCH = 28,
    SMOKE_DRIVE_STAGE_QUERY_ENUMERATION_END = 29,
    SMOKE_DRIVE_STAGE_QUERY_ENUMERATION_RESTART = 30,
    SMOKE_DRIVE_STAGE_QUERY_ENUMERATION_MISS = 31,
    SMOKE_DRIVE_STAGE_QUERY_ENUMERATION_GLOB = 32,
    SMOKE_DRIVE_STAGE_CLOSE_ENUMERATION_DIRECTORY = 33,
    SMOKE_DRIVE_STAGE_OPEN_LOCK_PRIMARY = 34,
    SMOKE_DRIVE_STAGE_OPEN_LOCK_SECONDARY = 35,
    SMOKE_DRIVE_STAGE_LOCK_SHARED_PRIMARY = 36,
    SMOKE_DRIVE_STAGE_LOCK_SHARED_SECONDARY = 37,
    SMOKE_DRIVE_STAGE_LOCK_EXCLUSIVE_SAME_HANDLE = 38,
    SMOKE_DRIVE_STAGE_UNLOCK_SHARED_SECONDARY = 39,
    SMOKE_DRIVE_STAGE_LOCK_EXCLUSIVE_CONFLICT = 40,
    SMOKE_DRIVE_STAGE_UNLOCK_SHARED_PRIMARY = 41,
    SMOKE_DRIVE_STAGE_LOCK_EXCLUSIVE_SECONDARY = 42,
    SMOKE_DRIVE_STAGE_UNLOCK_EXCLUSIVE_SECONDARY = 43,
    SMOKE_DRIVE_STAGE_CLOSE_LOCK_SECONDARY = 44,
    SMOKE_DRIVE_STAGE_CLOSE_LOCK_PRIMARY = 45,
    SMOKE_DRIVE_STAGE_OPEN_NOTIFY_DIRECTORY = 46,
    SMOKE_DRIVE_STAGE_NOTIFY_FIRST_PENDING = 47,
    SMOKE_DRIVE_STAGE_NOTIFY_FIRST_WAIT_COMPLETION = 48,
    SMOKE_DRIVE_STAGE_NOTIFY_CANCEL_PENDING = 49,
    SMOKE_DRIVE_STAGE_NOTIFY_LATE_PENDING = 50,
    SMOKE_DRIVE_STAGE_NOTIFY_LATE_DRAIN = 51,
    SMOKE_DRIVE_STAGE_NOTIFY_RECONNECT_READY = 52,
    SMOKE_DRIVE_STAGE_NOTIFY_RECONNECTING = 53,
    SMOKE_DRIVE_STAGE_NOTIFY_STALE_HANDLE = 54,
    SMOKE_DRIVE_STAGE_OPEN_NOTIFY_RECONNECTED_DIRECTORY = 55,
    SMOKE_DRIVE_STAGE_NOTIFY_UNSUPPORTED_FILTER = 56,
    SMOKE_DRIVE_STAGE_CLOSE_NOTIFY_RECONNECTED_DIRECTORY = 57,
    SMOKE_DRIVE_STAGE_OPEN_METADATA_FILE = 58,
    SMOKE_DRIVE_STAGE_SET_METADATA_BASIC = 59,
    SMOKE_DRIVE_STAGE_QUERY_METADATA_BASIC = 60,
    SMOKE_DRIVE_STAGE_SET_METADATA_SECURITY = 61,
    SMOKE_DRIVE_STAGE_QUERY_METADATA_SECURITY = 62,
    SMOKE_DRIVE_STAGE_QUERY_METADATA_EA = 63,
    SMOKE_DRIVE_STAGE_SET_METADATA_SPARSE = 64,
    SMOKE_DRIVE_STAGE_WRITE_METADATA_LARGE = 65,
    SMOKE_DRIVE_STAGE_QUERY_METADATA_ALL = 66,
    SMOKE_DRIVE_STAGE_QUERY_METADATA_RANGES = 67,
    SMOKE_DRIVE_STAGE_CLOSE_METADATA_FILE = 68,
    SMOKE_DRIVE_STAGE_REJECT_TRAVERSAL = 69,
    SMOKE_DRIVE_STAGE_REJECT_ABSOLUTE = 70,
    SMOKE_DRIVE_STAGE_REJECT_FINAL_SYMLINK = 71,
    SMOKE_DRIVE_STAGE_REJECT_DIRECTORY_SYMLINK = 72,
    SMOKE_DRIVE_STAGE_REJECT_FIFO = 73,
    SMOKE_DRIVE_STAGE_REJECT_SOCKET = 74,
    SMOKE_DRIVE_STAGE_OPEN_RACE_FILE = 75,
    SMOKE_DRIVE_STAGE_REJECT_RENAME_TRAVERSAL = 76,
    SMOKE_DRIVE_STAGE_REJECT_RENAME_RACE = 77,
    SMOKE_DRIVE_STAGE_CLOSE_RACE_FILE = 78,
    SMOKE_DRIVE_STAGE_REJECT_DEVICE_NODE = 79,
    SMOKE_DRIVE_STAGE_COMPLETE = 80,
    SMOKE_DRIVE_STAGE_FAILED = 81,
    SMOKE_DRIVE_STAGE_OPEN_LIMIT_PRIMARY = 82,
    SMOKE_DRIVE_STAGE_OPEN_LIMIT_SECONDARY = 83,
    SMOKE_DRIVE_STAGE_OPEN_LIMIT_TERTIARY = 84,
    SMOKE_DRIVE_STAGE_REJECT_LIMIT_QUATERNARY = 85,
    SMOKE_DRIVE_STAGE_WRITE_LIMIT_VALID = 86,
    SMOKE_DRIVE_STAGE_REJECT_LIMIT_WRITE_BYTES = 87,
    SMOKE_DRIVE_STAGE_REJECT_LIMIT_WRITE_SIZE = 88,
    SMOKE_DRIVE_STAGE_REJECT_LIMIT_SET_SIZE = 89,
    SMOKE_DRIVE_STAGE_REJECT_LIMIT_READ_BYTES = 90,
    SMOKE_DRIVE_STAGE_CLOSE_LIMIT_TERTIARY = 91,
    SMOKE_DRIVE_STAGE_CLOSE_LIMIT_SECONDARY = 92,
    SMOKE_DRIVE_STAGE_CLOSE_LIMIT_PRIMARY = 93,
    SMOKE_DRIVE_STAGE_OPEN_LIMIT_DIRECTORY_PRIMARY = 94,
    SMOKE_DRIVE_STAGE_OPEN_LIMIT_DIRECTORY_SECONDARY = 95,
    SMOKE_DRIVE_STAGE_OPEN_LIMIT_DIRECTORY_TERTIARY = 96,
    SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_FIRST_PENDING = 97,
    SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_SUBMIT_SECOND = 98,
    SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_SECOND_PENDING = 99,
    SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_SUBMIT_THIRD = 100,
    SMOKE_DRIVE_STAGE_REJECT_LIMIT_NOTIFY_THIRD = 101,
    SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_WAIT_CANCEL_FIRST = 102,
    SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_CANCEL_FIRST_PENDING = 103,
    SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_WAIT_CANCEL_SECOND = 104,
    SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_CANCEL_SECOND_PENDING = 105,
    SMOKE_DRIVE_STAGE_CLOSE_LIMIT_DIRECTORY_TERTIARY = 106,
    SMOKE_DRIVE_STAGE_CLOSE_LIMIT_DIRECTORY_SECONDARY = 107,
    SMOKE_DRIVE_STAGE_CLOSE_LIMIT_DIRECTORY_PRIMARY = 108
} smoke_drive_stage;

typedef struct smoke_drive_profile
{
    smoke_drive_mode mode;
} smoke_drive_profile;

static const smoke_drive_profile smoke_drive_read_only = {
    SMOKE_DRIVE_READ_ONLY,
};
static const smoke_drive_profile smoke_drive_writable = {
    SMOKE_DRIVE_WRITABLE,
};
static const smoke_drive_profile smoke_drive_information = {
    SMOKE_DRIVE_INFORMATION,
};
static const smoke_drive_profile smoke_drive_enumeration = {
    SMOKE_DRIVE_ENUMERATION,
};
static const smoke_drive_profile smoke_drive_locking = {
    SMOKE_DRIVE_LOCKING,
};
static const smoke_drive_profile smoke_drive_notify = {
    SMOKE_DRIVE_NOTIFY,
};
#if defined(RDP_HAVE_ATTR) && defined(__linux__)
static const smoke_drive_profile smoke_drive_metadata = {
    SMOKE_DRIVE_METADATA,
};
#endif
static const smoke_drive_profile smoke_drive_confinement = {
    SMOKE_DRIVE_CONFINEMENT,
};
static const smoke_drive_profile smoke_drive_device_node = {
    SMOKE_DRIVE_DEVICE_NODE,
};
static const smoke_drive_profile smoke_drive_limits = {
    SMOKE_DRIVE_LIMITS,
};
static const uint8_t smoke_drive_marker_data[] =
    "temporary client drive\n";
static const uint8_t smoke_drive_write_data[] = "write-data";
static const uint8_t smoke_drive_append_data[] = "-append";
static const uint8_t smoke_drive_metadata_xattr[] =
    "metadata-value";
static const uint8_t smoke_drive_outside_data[] = "outside-data";
static const uint8_t smoke_drive_race_original_data[] =
    "race-original";
static const uint8_t smoke_drive_race_replacement_data[] =
    "race-replacement";
static const uint8_t smoke_drive_limit_valid_data[] = {
    0x31u, 0x32u, 0x33u, 0x34u,
};
static const uint8_t smoke_drive_limit_oversized_data[] = {
    0x41u, 0x42u, 0x43u, 0x44u, 0x45u,
};

typedef struct smoke_drive_information_case
{
    uint32_t information_class;
    size_t minimum_length;
} smoke_drive_information_case;

static const smoke_drive_information_case
    smoke_drive_file_information_cases[] = {
        {RDP_SESSION_FILE_BASIC_INFORMATION, 36u},
        {RDP_SESSION_FILE_STANDARD_INFORMATION, 22u},
        {RDP_SESSION_FILE_INTERNAL_INFORMATION, 8u},
        {RDP_SESSION_FILE_EA_INFORMATION, 4u},
        {RDP_SESSION_FILE_ACCESS_INFORMATION, 4u},
        {RDP_SESSION_FILE_NAME_INFORMATION, 4u},
        {RDP_SESSION_FILE_NORMALIZED_NAME_INFORMATION, 4u},
        {RDP_SESSION_FILE_FULL_EA_INFORMATION, 0u},
        {RDP_SESSION_FILE_POSITION_INFORMATION, 8u},
        {RDP_SESSION_FILE_MODE_INFORMATION, 4u},
        {RDP_SESSION_FILE_ALIGNMENT_INFORMATION, 4u},
        {RDP_SESSION_FILE_ALL_INFORMATION, 100u},
        {RDP_SESSION_FILE_ALTERNATE_NAME_INFORMATION, 4u},
        {RDP_SESSION_FILE_STREAM_INFORMATION, 24u},
        {RDP_SESSION_FILE_COMPRESSION_INFORMATION, 16u},
        {RDP_SESSION_FILE_NETWORK_OPEN_INFORMATION, 56u},
        {RDP_SESSION_FILE_ATTRIBUTE_TAG_INFORMATION, 8u},
        {RDP_SESSION_FILE_ID_INFORMATION, 24u},
        {RDP_SESSION_FILE_CASE_SENSITIVE_INFORMATION, 4u},
        {RDP_SESSION_FILE_ALLOCATION_INFORMATION, 8u},
        {RDP_SESSION_FILE_END_OF_FILE_INFORMATION, 8u},
        {RDP_SESSION_FILE_VALID_DATA_LENGTH_INFORMATION, 8u},
};

static const smoke_drive_information_case
    smoke_drive_volume_information_cases[] = {
        {RDP_FILESYSTEM_REDIRECTION_FS_VOLUME_INFORMATION, 17u},
        {RDP_FILESYSTEM_REDIRECTION_FS_LABEL_INFORMATION, 4u},
        {RDP_FILESYSTEM_REDIRECTION_FS_SIZE_INFORMATION, 24u},
        {RDP_FILESYSTEM_REDIRECTION_FS_DEVICE_INFORMATION, 8u},
        {RDP_FILESYSTEM_REDIRECTION_FS_ATTRIBUTE_INFORMATION, 12u},
        {RDP_FILESYSTEM_REDIRECTION_FS_CONTROL_INFORMATION, 48u},
        {RDP_FILESYSTEM_REDIRECTION_FS_FULL_SIZE_INFORMATION, 32u},
        {RDP_FILESYSTEM_REDIRECTION_FS_OBJECT_ID_INFORMATION, 64u},
        {RDP_FILESYSTEM_REDIRECTION_FS_VOLUME_FLAGS_INFORMATION, 4u},
        {RDP_FILESYSTEM_REDIRECTION_FS_SECTOR_SIZE_INFORMATION, 28u},
};

static const uint32_t smoke_drive_security_information_cases[] = {
    RDP_FILESYSTEM_REDIRECTION_OWNER_SECURITY_INFORMATION,
    RDP_FILESYSTEM_REDIRECTION_GROUP_SECURITY_INFORMATION,
    RDP_FILESYSTEM_REDIRECTION_DACL_SECURITY_INFORMATION,
    RDP_FILESYSTEM_REDIRECTION_SUPPORTED_SECURITY_INFORMATION,
};

static const smoke_drive_information_case
    smoke_drive_directory_information_cases[] = {
        {RDP_SESSION_FILE_DIRECTORY_INFORMATION, 64u},
        {RDP_SESSION_FILE_FULL_DIRECTORY_INFORMATION, 68u},
        {RDP_SESSION_FILE_BOTH_DIRECTORY_INFORMATION, 94u},
        {RDP_SESSION_FILE_NAMES_INFORMATION, 12u},
        {RDP_SESSION_FILE_ID_BOTH_DIRECTORY_INFORMATION, 102u},
        {RDP_SESSION_FILE_ID_FULL_DIRECTORY_INFORMATION, 76u},
        {RDP_SESSION_FILE_ID_EXTD_DIRECTORY_INFORMATION, 88u},
        {RDP_SESSION_FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION, 114u},
        {RDP_SESSION_FILE_ID_64_EXTD_DIRECTORY_INFORMATION, 80u},
        {RDP_SESSION_FILE_ID_64_EXTD_BOTH_DIRECTORY_INFORMATION, 106u},
        {RDP_SESSION_FILE_ID_ALL_EXTD_DIRECTORY_INFORMATION, 96u},
        {RDP_SESSION_FILE_ID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION, 122u},
};

typedef struct smoke_drive_confinement_fixture
{
    char outside_directory[160];
    char outside_file[192];
    char outside_escape[192];
    char final_symlink[192];
    char directory_symlink[192];
    char fifo[192];
    char socket[192];
    char race[192];
    char race_original[192];
    char race_renamed[192];
    char root_escape[192];
    int socket_fd;
    int race_swapped;
} smoke_drive_confinement_fixture;

typedef struct smoke_platform
{
    server_platform_capture_sink capture_sink;
    server_platform_drive_sink drive_sink;
    server_platform_permission_sink permission_sink;
    atomic_uint capture_requests;
    atomic_uint capture_variant;
    atomic_uint key_events;
    atomic_uint unicode_events;
    atomic_uint mouse_events;
    atomic_uint extended_mouse_events;
    atomic_uint input_validation_errors;
    atomic_uint drive_presentations;
    atomic_uint drive_removals;
    atomic_uint drive_stage;
    atomic_uint drive_completions;
    atomic_uint drive_wait_cycles;
    atomic_uint releases;
    atomic_uint refresh_requests;
    atomic_uint output_suppressions;
    atomic_uint output_resumptions;
    char drive_name[64];
    server_platform_drive_volume drive_volume;
    librdp_server_drive_file_handle drive_file;
    librdp_server_drive_file_handle drive_secondary_file;
    librdp_server_drive_file_handle drive_directory;
    uint64_t drive_next_request_id;
    uint64_t drive_pending_request_ids[2];
    uint32_t drive_previous_generation;
    librdp_status drive_failure_status;
    uint32_t drive_failure_io_status;
    const smoke_drive_profile* drive_profile;
    smoke_drive_confinement_fixture* drive_confinement;
    size_t drive_sequence_index;
    uint8_t pixels[SMOKE_PIXEL_BYTES];
    uint8_t alternate_pixels[SMOKE_PIXEL_BYTES];
} smoke_platform;

static int smoke_drive_confinement_swap_race(
    smoke_drive_confinement_fixture* fixture);

typedef struct smoke_host
{
    server_host* host;
    pthread_t thread;
    atomic_uint port;
    librdp_status status;
} smoke_host;

typedef struct smoke_auth_redirection
{
    atomic_uint open_requested;
    atomic_uint channel_opened;
    atomic_uint call_sent;
    atomic_uint response_received;
    atomic_uint cancellation_verified;
    atomic_int failure_status;
} smoke_auth_redirection;

typedef struct smoke_nla_stall
{
    librdp_server_config config;
    pthread_t thread;
    atomic_uint port;
    atomic_uint stop;
    atomic_uint authenticating;
    librdp_status status;
} smoke_nla_stall;

typedef enum smoke_integrity_tamper
{
    SMOKE_INTEGRITY_SLOWPATH_MAC = 1,
    SMOKE_INTEGRITY_FASTPATH_MAC = 2,
    SMOKE_INTEGRITY_SLOWPATH_CIPHERTEXT = 3
} smoke_integrity_tamper;

typedef enum smoke_gateway_credentials
{
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT = 0,
    SMOKE_GATEWAY_CREDENTIALS_SESSION = 1,
    SMOKE_GATEWAY_CREDENTIALS_NONE = 2
} smoke_gateway_credentials;

typedef struct smoke_gateway_profile
{
    librdp_gateway_mode mode;
    smoke_gateway_credentials credentials;
    test_http_proxy_behavior proxy_behavior;
    int reject_credentials;
    int trust_certificate;
    uint32_t timeout_ms;
    librdp_status expected_status;
    librdp_status expected_fixture_status;
    test_rdg_stream drop_stream;
} smoke_gateway_profile;

static const smoke_gateway_profile smoke_gateway_http_explicit = {
    LIBRDP_GATEWAY_HTTP_CONNECT,
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT,
    TEST_HTTP_PROXY_FORWARD,
    0,
    1,
    5000u,
    LIBRDP_STATUS_OK,
    LIBRDP_STATUS_OK,
    TEST_RDG_STREAM_NONE,
};
static const smoke_gateway_profile smoke_gateway_http_session = {
    LIBRDP_GATEWAY_HTTP_CONNECT,
    SMOKE_GATEWAY_CREDENTIALS_SESSION,
    TEST_HTTP_PROXY_FORWARD,
    0,
    1,
    5000u,
    LIBRDP_STATUS_OK,
    LIBRDP_STATUS_OK,
    TEST_RDG_STREAM_NONE,
};
static const smoke_gateway_profile smoke_gateway_http_no_credentials = {
    LIBRDP_GATEWAY_HTTP_CONNECT,
    SMOKE_GATEWAY_CREDENTIALS_NONE,
    TEST_HTTP_PROXY_FORWARD,
    0,
    1,
    5000u,
    LIBRDP_STATUS_AUTHENTICATION_FAILED,
    LIBRDP_STATUS_IO_ERROR,
    TEST_RDG_STREAM_NONE,
};
static const smoke_gateway_profile smoke_gateway_rdg = {
    LIBRDP_GATEWAY_RDG_HTTP,
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT,
    TEST_HTTP_PROXY_FORWARD,
    0,
    1,
    5000u,
    LIBRDP_STATUS_OK,
    LIBRDP_STATUS_OK,
    TEST_RDG_STREAM_NONE,
};
static const smoke_gateway_profile smoke_gateway_rdg_drop_out = {
    LIBRDP_GATEWAY_RDG_HTTP,
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT,
    TEST_HTTP_PROXY_FORWARD,
    0,
    1,
    5000u,
    LIBRDP_STATUS_OK,
    LIBRDP_STATUS_IO_ERROR,
    TEST_RDG_STREAM_OUT,
};
static const smoke_gateway_profile smoke_gateway_rdg_drop_in = {
    LIBRDP_GATEWAY_RDG_HTTP,
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT,
    TEST_HTTP_PROXY_FORWARD,
    0,
    1,
    5000u,
    LIBRDP_STATUS_OK,
    LIBRDP_STATUS_IO_ERROR,
    TEST_RDG_STREAM_IN,
};
static const smoke_gateway_profile smoke_gateway_http_auth_failure = {
    LIBRDP_GATEWAY_HTTP_CONNECT,
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT,
    TEST_HTTP_PROXY_FORWARD,
    1,
    1,
    5000u,
    LIBRDP_STATUS_AUTHENTICATION_FAILED,
    LIBRDP_STATUS_IO_ERROR,
    TEST_RDG_STREAM_NONE,
};
static const smoke_gateway_profile smoke_gateway_http_timeout = {
    LIBRDP_GATEWAY_HTTP_CONNECT,
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT,
    TEST_HTTP_PROXY_STALL,
    0,
    1,
    100u,
    LIBRDP_STATUS_TIMEOUT,
    LIBRDP_STATUS_TIMEOUT,
    TEST_RDG_STREAM_NONE,
};
static const smoke_gateway_profile smoke_gateway_http_malformed = {
    LIBRDP_GATEWAY_HTTP_CONNECT,
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT,
    TEST_HTTP_PROXY_MALFORMED_RESPONSE,
    0,
    1,
    5000u,
    LIBRDP_STATUS_IO_ERROR,
    LIBRDP_STATUS_PROTOCOL_ERROR,
    TEST_RDG_STREAM_NONE,
};
static const smoke_gateway_profile smoke_gateway_http_refused = {
    LIBRDP_GATEWAY_HTTP_CONNECT,
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT,
    TEST_HTTP_PROXY_REFUSE,
    0,
    1,
    5000u,
    LIBRDP_STATUS_IO_ERROR,
    LIBRDP_STATUS_CLOSED,
    TEST_RDG_STREAM_NONE,
};
static const smoke_gateway_profile smoke_gateway_rdg_untrusted = {
    LIBRDP_GATEWAY_RDG_HTTP,
    SMOKE_GATEWAY_CREDENTIALS_EXPLICIT,
    TEST_HTTP_PROXY_FORWARD,
    0,
    0,
    5000u,
    LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED,
    LIBRDP_STATUS_IO_ERROR,
    TEST_RDG_STREAM_NONE,
};

typedef struct smoke_integrity_peer
{
    librdp_server_config config;
    pthread_t thread;
    atomic_uint port;
    atomic_uint packet_sent;
    atomic_uint client_closed;
    smoke_integrity_tamper tamper;
    librdp_status status;
} smoke_integrity_peer;

typedef librdp_status (*smoke_fastpath_send_fn)(
    librdp_server_peer* peer);

typedef enum smoke_graphics_mode
{
    SMOKE_GRAPHICS_PLANAR = 0,
    SMOKE_GRAPHICS_PROGRESSIVE = 1,
    SMOKE_GRAPHICS_LIFECYCLE = 2,
    SMOKE_GRAPHICS_MULTI_SURFACE = 3,
    SMOKE_GRAPHICS_CLEARCODEC = 4,
    SMOKE_GRAPHICS_AVC = 5,
    SMOKE_GRAPHICS_BACKPRESSURE = 6,
    SMOKE_GRAPHICS_MOTION = 7
} smoke_graphics_mode;

enum
{
    SMOKE_AVC_SURFACE_DIMENSION = 17,
    SMOKE_AVC_SURFACE_COUNT = 6,
    SMOKE_AVC_LAYOUT_COLUMNS = 3,
    SMOKE_AVC_LAYOUT_GAP = 1,
    SMOKE_SLOW_PRESENTER_DELAY_MS = 80,
    SMOKE_GRAPHICS_MOTION_FRAME_COUNT = 96,
    SMOKE_GRAPHICS_MOTION_UPDATE_COUNT =
        SMOKE_GRAPHICS_MOTION_FRAME_COUNT * 2 - 1,
    SMOKE_GRAPHICS_MOTION_PUMP_LIMIT = 2000
};

typedef struct smoke_fastpath_peer
{
    librdp_server_config config;
    pthread_t thread;
    atomic_uint port;
    atomic_uint packet_sent;
    atomic_uint client_closed;
    smoke_fastpath_send_fn send;
    librdp_status status;
} smoke_fastpath_peer;

typedef struct smoke_graphics_peer
{
    librdp_server_config config;
    pthread_t thread;
    atomic_uint port;
    atomic_uint connections;
    atomic_uint caps_advertised;
    atomic_uint frame_acknowledged;
    atomic_uint frame_sent;
    atomic_uint client_closed;
    uint32_t maximum_pending_frames;
    uint32_t backpressure_rejections;
    uint32_t acknowledgement_timeouts;
    uint32_t last_ack_frame_id;
    uint32_t last_ack_total_frames;
    uint64_t first_ack_delay_ns;
    unsigned int acknowledgement_sequence_errors;
    int progressive;
    int reconnect;
    int multi_surface;
    int clearcodec;
    int avc;
    int backpressure;
    int motion;
    librdp_status status;
} smoke_graphics_peer;

typedef struct smoke_slow_presenter
{
    unsigned int frame_begins;
    unsigned int frame_ends;
    uint32_t delay_ms;
} smoke_slow_presenter;

typedef struct smoke_motion_presenter
{
    unsigned int frame_begins;
    unsigned int frame_ends;
    unsigned int pixel_rects;
    unsigned int protocol_errors;
    uint32_t active_frame_id;
} smoke_motion_presenter;

typedef struct smoke_redirection_peer
{
    librdp_server_config config;
    pthread_t thread;
    atomic_uint port;
    atomic_uint stop;
    atomic_uint connections;
    atomic_uint redirects;
    atomic_uint route_verified;
    int enhanced;
    int loop;
    librdp_status status;
} smoke_redirection_peer;

typedef enum smoke_security_peer_mode
{
    SMOKE_SECURITY_PEER_DOWNGRADE = 1,
    SMOKE_SECURITY_PEER_TLS_CERTIFICATE = 2,
    SMOKE_SECURITY_PEER_TLS_INVALID = 3
} smoke_security_peer_mode;

typedef struct smoke_security_peer
{
    pthread_t thread;
    atomic_uint port;
    atomic_uint stop;
    smoke_security_peer_mode mode;
    const char* certificate_path;
    const char* private_key_path;
    librdp_status status;
} smoke_security_peer;

typedef struct smoke_client_events
{
    unsigned int state_events;
    unsigned int surface_events;
    unsigned int error_events;
    unsigned int clipboard_format_events;
    unsigned int clipboard_data_events;
    unsigned int clipboard_request_events;
    unsigned int clipboard_failures;
    const server_client_clipboard_profile* clipboard_profile;
    server_client_clipboard_provider* clipboard_provider;
    int clipboard_data_requested;
    int active;
    int active_seen;
} smoke_client_events;

typedef struct smoke_nla_provider
{
    librdp_status status;
    unsigned int calls;
    const smoke_nla_identity* expected_identity;
    int identity_matched;
} smoke_nla_provider;

typedef struct smoke_trace_capture
{
    unsigned int records;
    unsigned int connect_starts;
    unsigned int connect_completions;
    unsigned int directory_notify_requests;
    unsigned int directory_notify_completions;
    unsigned int client_connect_successes;
    unsigned int client_connect_failures;
    unsigned int client_connect_cancellations;
    unsigned int credssp_failures;
    unsigned int slowpath_integrity_failures;
    unsigned int fastpath_integrity_failures;
    unsigned int integrity_failures;
    unsigned int security_downgrades;
    unsigned int tls_connect_failures;
    unsigned int tls_verify_failures;
    unsigned int gateway_connect_starts;
    unsigned int gateway_connect_completions;
    unsigned int rdg_connect_starts;
    unsigned int rdg_connect_completions;
    unsigned int rdg_handshakes;
    unsigned int rdg_tunnels;
    unsigned int rdg_authentications;
    unsigned int rdg_channels;
    unsigned int redirections;
    unsigned int redirection_reconnects;
    unsigned int redirection_loops;
    unsigned int slowpath_bitmap_updates;
    unsigned int fastpath_bitmap_updates;
    unsigned int surface_nscodec_updates;
    unsigned int surface_rfx_updates;
    unsigned int surface_rfx_tiles;
    unsigned int graphics_caps_confirms;
    unsigned int graphics_resets;
    unsigned int graphics_surface_creates;
    unsigned int graphics_surface_maps;
    unsigned int graphics_planar_updates;
    unsigned int graphics_uncompressed_updates;
    unsigned int graphics_clearcodec_updates;
    unsigned int graphics_avc420_updates;
    unsigned int graphics_avc444_updates;
    unsigned int graphics_avc444v2_updates;
    unsigned int graphics_avc420_decodes;
    unsigned int graphics_avc444_decodes;
    unsigned int graphics_avc444v2_decodes;
    uint32_t graphics_avc_support;
    unsigned int graphics_progressive_first_updates;
    unsigned int graphics_progressive_upgrade_updates;
    unsigned int graphics_progressive_missing_tiles;
    unsigned int graphics_context_deletes;
    unsigned int graphics_frame_starts;
    unsigned int graphics_frame_ends;
    unsigned int graphics_frame_acks;
    unsigned int graphics_surface_deletes;
    unsigned int refresh_requests;
    unsigned int output_suppressions;
    unsigned int output_resumptions;
    unsigned int clipboard_format_lists;
    unsigned int clipboard_requests;
    unsigned int clipboard_responses;
    unsigned int clipboard_local_responses;
    unsigned int clipboard_file_requests;
    unsigned int clipboard_file_inbound_requests;
    unsigned int clipboard_file_responses;
    unsigned int cancel_requests;
    int cancel_phase;
    librdp_status cancel_status;
    librdp_session_lifecycle lifecycle[SMOKE_LIFECYCLE_CAPACITY];
    size_t lifecycle_count;
    char recent[SMOKE_TRACE_RECENT_CAPACITY]
               [SMOKE_TRACE_RECENT_LINE];
    size_t recent_count;
    size_t recent_next;
    int lifecycle_overflow;
    int leaked;
    int address_matched;
    const smoke_nla_identity* identity;
    const smoke_nla_identity* gateway_identity;
    const char* sensitive_canary;
    const char* target;
    uint16_t port;
} smoke_trace_capture;

static int smoke_check(int condition, const char* expression, int line)
{
    if (condition)
        return 0;
    fprintf(stderr,
            "test_server_client_smoke:%d: check failed: %s\n",
            line,
            expression);
    return 1;
}

#define CHECK(expression)                                                                           \
    do                                                                                              \
    {                                                                                               \
        if (smoke_check((expression), #expression, __LINE__) != 0)                                 \
            return 1;                                                                               \
    } while (0)

#define REQUIRE(expression)                                                                         \
    do                                                                                              \
    {                                                                                               \
        if (smoke_check((expression), #expression, __LINE__) != 0)                                 \
        {                                                                                           \
            result = 1;                                                                             \
            goto cleanup;                                                                           \
        }                                                                                           \
    } while (0)

static uint64_t smoke_now_ns(void)
{
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return 0u;
    return (uint64_t)value.tv_sec * 1000000000u + (uint64_t)value.tv_nsec;
}

/*
 * Hash a complete presented surface with the mandatory crypto backend. Fixed
 * digests detect row-order, stride, tiling, and partial-update regressions
 * without retaining image artifacts.
 */
static int smoke_frame_matches_sha256(
    const uint8_t* pixels,
    size_t pixels_len,
    const uint8_t expected[SMOKE_SHA256_BYTES])
{
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0u;

    if (!pixels || !expected ||
        EVP_Digest(pixels,
                   pixels_len,
                   digest,
                   &digest_len,
                   EVP_sha256(),
                   NULL) != 1)
        return 0;
    return digest_len == SMOKE_SHA256_BYTES &&
           CRYPTO_memcmp(digest,
                         expected,
                         SMOKE_SHA256_BYTES) == 0;
}

static librdp_status smoke_nla_credentials_provider(
    librdp_server_peer* peer,
    const librdp_server_credentials_request* request,
    librdp_credentials* credentials,
    void* user_data)
{
    smoke_nla_provider* provider = (smoke_nla_provider*)user_data;

    if (!peer || !request || !credentials || !provider)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    provider->calls++;
    if (provider->expected_identity)
    {
        const char* expected_domain =
            provider->expected_identity->domain;

        provider->identity_matched =
            request->username &&
            strcmp(request->username,
                   provider->expected_identity->username) == 0 &&
            ((!expected_domain && !request->domain) ||
             (expected_domain && request->domain &&
              strcmp(request->domain, expected_domain) == 0));
    }
    return provider->status;
}

static void smoke_trace_callback(librdp_session* session,
                                 const librdp_trace_record* record,
                                 void* user_data)
{
    smoke_trace_capture* capture = (smoke_trace_capture*)user_data;
    char expected_address[320] = {0};

    (void)session;
    if (!capture || !record || !record->line)
        return;
    if (getenv("LIBRDP_SMOKE_TRACE_OUTPUT"))
        fprintf(stderr, "%s\n", record->line);
    (void)snprintf(
        capture->recent[capture->recent_next],
        sizeof(capture->recent[capture->recent_next]),
        "%s",
        record->line);
    capture->recent_next =
        (capture->recent_next + 1u) %
        SMOKE_TRACE_RECENT_CAPACITY;
    if (capture->recent_count <
        SMOKE_TRACE_RECENT_CAPACITY)
        capture->recent_count++;
    capture->records++;
    if (record->event &&
        strcmp(record->event, "transport.tcp.connect.start") == 0)
    {
        capture->connect_starts++;
        if (capture->target && record->message &&
            snprintf(expected_address,
                     sizeof(expected_address),
                     "host=%s port=%u",
                     capture->target,
                     (unsigned int)capture->port) > 0 &&
            strcmp(record->message, expected_address) == 0)
            capture->address_matched = 1;
    }
    else if (record->event &&
             strcmp(record->event, "transport.tcp.connect.done") == 0)
        capture->connect_completions++;
    else if (record->event &&
             strcmp(record->event,
                    "client.rdpdr.file.notify_change") == 0)
        capture->directory_notify_requests++;
    else if (record->event &&
             strcmp(record->event,
                    "client.rdpdr.file.notify_change.completed") == 0)
        capture->directory_notify_completions++;
    else if (record->event &&
             strcmp(record->event, "client.connect.done") == 0)
        capture->client_connect_successes++;
    else if (record->event &&
             strcmp(record->event, "client.connect.failed") == 0)
        capture->client_connect_failures++;
    else if (record->event &&
             strcmp(record->event, "client.connect.cancelled") == 0)
        capture->client_connect_cancellations++;
    else if (record->event &&
             strcmp(record->event, "credssp.nla.failed") == 0)
        capture->credssp_failures++;
    else if (record->event &&
             strcmp(record->event,
                    "rdp.security.signature.mismatch") == 0)
        capture->slowpath_integrity_failures++;
    else if (record->event &&
             strcmp(record->event,
                    "rdp.fastpath.signature.mismatch") == 0)
        capture->fastpath_integrity_failures++;
    else if (record->event &&
             strcmp(record->event,
                    "rdp.security.integrity.failed") == 0)
        capture->integrity_failures++;
    else if (record->event &&
             strcmp(record->event,
                    "x224.negotiation.downgrade") == 0)
        capture->security_downgrades++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.tls.connect.failed") == 0)
        capture->tls_connect_failures++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.tls.verify.failed") == 0)
        capture->tls_verify_failures++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.gateway.connect.start") == 0)
        capture->gateway_connect_starts++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.gateway.connect.done") == 0)
        capture->gateway_connect_completions++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.gateway.rdg.connect.start") == 0)
        capture->rdg_connect_starts++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.gateway.rdg.connect.done") == 0)
        capture->rdg_connect_completions++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.gateway.rdg.handshake.done") == 0)
        capture->rdg_handshakes++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.gateway.rdg.tunnel.done") == 0)
        capture->rdg_tunnels++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.gateway.rdg.auth.done") == 0)
        capture->rdg_authentications++;
    else if (record->event &&
             strcmp(record->event,
                    "transport.gateway.rdg.channel.done") == 0)
        capture->rdg_channels++;
    else if (record->event &&
             strcmp(record->event,
                    "client.redirection.received") == 0)
        capture->redirections++;
    else if (record->event &&
             strcmp(record->event,
                    "client.redirection.reconnect.done") == 0)
        capture->redirection_reconnects++;
    else if (record->event &&
             strcmp(record->event,
                    "client.redirection.loop_rejected") == 0)
        capture->redirection_loops++;
    else if (record->event &&
             strcmp(record->event,
                    "rdp.slowpath.bitmap_update") == 0)
        capture->slowpath_bitmap_updates++;
    else if (record->event &&
             strcmp(record->event,
                    "rdp.fastpath.bitmap_update") == 0)
        capture->fastpath_bitmap_updates++;
    else if (record->event &&
             strcmp(record->event,
                    "client.surface.bits.blit") == 0 &&
             record->message &&
             strstr(record->message, "codec_id=1 ") != NULL)
        capture->surface_nscodec_updates++;
    else if (record->event &&
             strcmp(record->event,
                    "client.surface.rfx.blit") == 0 &&
             record->message)
    {
        unsigned int tiles = 0u;

        capture->surface_rfx_updates++;
        if (sscanf(record->message,
                   "frame_id=%*u width=%*u height=%*u tiles=%u",
                   &tiles) == 1)
            capture->surface_rfx_tiles += tiles;
    }
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.caps_advertise") == 0 &&
             record->message)
    {
        unsigned int avc_support = 0u;

        if (sscanf(record->message,
                   "dvc_channel_id=%*u payload_len=%*u avc_support=%u",
                   &avc_support) == 1)
            capture->graphics_avc_support = avc_support;
    }
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.caps_confirm") == 0)
        capture->graphics_caps_confirms++;
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.reset") == 0)
        capture->graphics_resets++;
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.surface.create") == 0)
        capture->graphics_surface_creates++;
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.surface.map_output") == 0)
        capture->graphics_surface_maps++;
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.wire_to_surface") == 0 &&
             record->message)
    {
        unsigned int codec_id = 0u;

        if (sscanf(record->message,
                   "dvc_channel_id=%*u surface_id=%*u codec_id=%u",
                   &codec_id) == 1)
        {
            switch (codec_id)
            {
                case RDP_GRAPHICS_CODECID_UNCOMPRESSED:
                    capture->graphics_uncompressed_updates++;
                    break;
                case RDP_GRAPHICS_CODECID_CLEARCODEC:
                    capture->graphics_clearcodec_updates++;
                    break;
                case RDP_GRAPHICS_CODECID_PLANAR:
                    capture->graphics_planar_updates++;
                    break;
                case RDP_GRAPHICS_CODECID_AVC420:
                    capture->graphics_avc420_updates++;
                    break;
                case RDP_GRAPHICS_CODECID_AVC444:
                    capture->graphics_avc444_updates++;
                    break;
                case RDP_GRAPHICS_CODECID_AVC444V2:
                    capture->graphics_avc444v2_updates++;
                    break;
                default:
                    break;
            }
        }
    }
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.avc420.decode.done") == 0)
        capture->graphics_avc420_decodes++;
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.avc444.decode.done") == 0 &&
             record->message)
    {
        unsigned int codec_id = 0u;

        if (sscanf(record->message,
                   "status=%*d codec_id=%u",
                   &codec_id) == 1)
        {
            if (codec_id == RDP_GRAPHICS_CODECID_AVC444)
                capture->graphics_avc444_decodes++;
            else if (codec_id ==
                     RDP_GRAPHICS_CODECID_AVC444V2)
                capture->graphics_avc444v2_decodes++;
        }
    }
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.progressive") == 0 &&
             record->message)
    {
        if (strstr(record->message, "first_tiles=1 ") != NULL)
            capture->graphics_progressive_first_updates++;
        if (strstr(record->message, "upgrade_tiles=1 ") != NULL)
            capture->graphics_progressive_upgrade_updates++;
    }
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.progressive.tile.missing") == 0)
        capture->graphics_progressive_missing_tiles++;
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.encoding_context.delete") == 0)
        capture->graphics_context_deletes++;
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.frame.start") == 0)
        capture->graphics_frame_starts++;
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.frame.end") == 0)
        capture->graphics_frame_ends++;
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.frame_ack") == 0)
        capture->graphics_frame_acks++;
    else if (record->event &&
             strcmp(record->event,
                    "client.graphics.surface.delete") == 0)
        capture->graphics_surface_deletes++;
    else if (record->event &&
             strcmp(record->event,
                    "client.active.refresh_rect") == 0)
        capture->refresh_requests++;
    else if (record->event &&
             strcmp(record->event,
                    "client.active.output.suppressed") == 0)
        capture->output_suppressions++;
    else if (record->event &&
             strcmp(record->event,
                    "client.active.output.resumed") == 0)
        capture->output_resumptions++;
    else if (record->event &&
             strcmp(record->event,
                    "client.clipboard.format_list") == 0)
        capture->clipboard_format_lists++;
    else if (record->event &&
             strcmp(record->event,
                    "client.clipboard.request_data") == 0)
        capture->clipboard_requests++;
    else if (record->event &&
             strcmp(record->event,
                    "client.clipboard.format_data_response") == 0 &&
             record->category &&
             strcmp(record->category, "client") == 0)
        capture->clipboard_responses++;
    else if (record->event &&
             strcmp(record->event,
                    "client.clipboard.format_data_response.local") == 0)
        capture->clipboard_local_responses++;
    else if (record->event &&
             strcmp(record->event,
                    "client.clipboard.request_file") == 0)
        capture->clipboard_file_requests++;
    else if (record->event &&
             strcmp(record->event,
                    "client.clipboard.filecontents_request") == 0 &&
             record->category &&
             strcmp(record->category, "client") == 0)
        capture->clipboard_file_inbound_requests++;
    else if (record->event &&
             strcmp(record->event,
                    "client.clipboard.filecontents_response") == 0 &&
             record->category &&
             strcmp(record->category, "client") == 0)
        capture->clipboard_file_responses++;
    else if (record->event &&
             strcmp(record->event, "client.lifecycle") == 0 &&
             record->message)
    {
        unsigned long phase = 0ul;
        char* end = NULL;

        errno = 0;
        if (strncmp(record->message, "phase=", 6u) == 0)
        {
            phase = strtoul(record->message + 6u, &end, 10);
            if (errno == 0 && end && *end == '\0' &&
                phase <= (unsigned long)LIBRDP_LIFECYCLE_FAILED)
            {
                if (capture->lifecycle_count <
                    SMOKE_LIFECYCLE_CAPACITY)
                {
                    capture->lifecycle[capture->lifecycle_count++] =
                        (librdp_session_lifecycle)phase;
                }
                else
                    capture->lifecycle_overflow = 1;
                if (capture->cancel_phase == (int)phase &&
                    capture->cancel_requests == 0u)
                {
                    capture->cancel_requests++;
                    capture->cancel_status =
                        librdp_session_cancel(session);
                }
            }
        }
    }
    {
        const smoke_nla_identity* identities[2] = {
            capture->identity,
            capture->gateway_identity
        };
        size_t index = 0u;

        for (index = 0u; index < 2u; index++)
        {
            const smoke_nla_identity* identity = identities[index];

            if (!identity)
                continue;
            if ((identity->username &&
                 strstr(record->line, identity->username)) ||
                (identity->password &&
                 strstr(record->line, identity->password)) ||
                (identity->domain && identity->domain[0] != '\0' &&
                 strstr(record->line, identity->domain)))
                capture->leaked = 1;
        }
        if (capture->sensitive_canary &&
            strstr(record->line, capture->sensitive_canary))
            capture->leaked = 1;
    }
}

/*
 * Validate the complete lifecycle observed through the per-session trace.
 * Negotiation and authentication may alternate while Standard Security or NLA
 * exchanges are in progress, but terminal and transport phases remain strict.
 */
static int smoke_validate_lifecycle(
    const smoke_trace_capture* capture,
    librdp_security_mode security)
{
    size_t index = 0u;
    size_t connecting_index = SIZE_MAX;
    size_t tls_index = SIZE_MAX;
    size_t authenticating_index = SIZE_MAX;
    size_t activating_index = SIZE_MAX;
    size_t active_index = SIZE_MAX;
    size_t disconnecting_index = SIZE_MAX;
    size_t disconnected_index = SIZE_MAX;
    unsigned int connecting_count = 0u;
    unsigned int tls_count = 0u;
    unsigned int activating_count = 0u;
    unsigned int active_count = 0u;
    unsigned int disconnecting_count = 0u;
    unsigned int disconnected_count = 0u;

    if (!capture || capture->lifecycle_overflow ||
        capture->lifecycle_count < 7u ||
        capture->lifecycle[0] != LIBRDP_LIFECYCLE_NEW)
        return 0;
    for (index = 1u; index < capture->lifecycle_count; index++)
    {
        librdp_session_lifecycle phase = capture->lifecycle[index];

        if (phase == capture->lifecycle[index - 1u] ||
            phase == LIBRDP_LIFECYCLE_FAILED ||
            phase == LIBRDP_LIFECYCLE_RECONNECTING)
            return 0;
        switch (phase)
        {
            case LIBRDP_LIFECYCLE_RESOLVING:
                if (connecting_index != SIZE_MAX)
                    return 0;
                break;
            case LIBRDP_LIFECYCLE_CONNECTING:
                connecting_count++;
                connecting_index = index;
                break;
            case LIBRDP_LIFECYCLE_TLS_HANDSHAKE:
                tls_count++;
                tls_index = index;
                break;
            case LIBRDP_LIFECYCLE_AUTHENTICATING:
                if (authenticating_index == SIZE_MAX)
                    authenticating_index = index;
                break;
            case LIBRDP_LIFECYCLE_NEGOTIATING:
                break;
            case LIBRDP_LIFECYCLE_ACTIVATING:
                activating_count++;
                activating_index = index;
                break;
            case LIBRDP_LIFECYCLE_ACTIVE:
                active_count++;
                active_index = index;
                break;
            case LIBRDP_LIFECYCLE_DISCONNECTING:
                disconnecting_count++;
                disconnecting_index = index;
                break;
            case LIBRDP_LIFECYCLE_DISCONNECTED:
                disconnected_count++;
                disconnected_index = index;
                break;
            default:
                return 0;
        }
    }
    if (connecting_count != 1u || activating_count != 1u ||
        active_count != 1u || disconnecting_count != 1u ||
        disconnected_count != 1u ||
        authenticating_index == SIZE_MAX ||
        !(connecting_index < authenticating_index &&
          authenticating_index < activating_index &&
          activating_index < active_index &&
          active_index < disconnecting_index &&
          disconnecting_index < disconnected_index) ||
        disconnected_index + 1u != capture->lifecycle_count)
        return 0;
    if (security == LIBRDP_SECURITY_STANDARD)
        return tls_count == 0u;
    return tls_count == 1u && connecting_index < tls_index &&
           tls_index < authenticating_index;
}

/*
 * Validate two complete Standard Security lifecycles separated by the public
 * reconnect transition. This is intentionally separate from the single-cycle
 * validator so an incomplete teardown cannot be hidden by aggregate counts.
 */
static int smoke_validate_reconnect_lifecycle(
    const smoke_trace_capture* capture)
{
    size_t first_active = SIZE_MAX;
    size_t first_disconnected = SIZE_MAX;
    size_t reconnecting = SIZE_MAX;
    size_t second_connecting = SIZE_MAX;
    size_t second_active = SIZE_MAX;
    size_t final_disconnected = SIZE_MAX;
    unsigned int connecting_count = 0u;
    unsigned int active_count = 0u;
    unsigned int disconnecting_count = 0u;
    unsigned int disconnected_count = 0u;
    size_t index = 0u;

    if (!capture || capture->lifecycle_overflow ||
        capture->lifecycle_count < 14u ||
        capture->lifecycle[0] != LIBRDP_LIFECYCLE_NEW)
        return 0;
    for (index = 1u; index < capture->lifecycle_count; index++)
    {
        librdp_session_lifecycle phase = capture->lifecycle[index];

        if (phase == capture->lifecycle[index - 1u] ||
            phase == LIBRDP_LIFECYCLE_FAILED ||
            phase == LIBRDP_LIFECYCLE_TLS_HANDSHAKE)
            return 0;
        if (phase == LIBRDP_LIFECYCLE_CONNECTING)
        {
            connecting_count++;
            if (connecting_count == 2u)
                second_connecting = index;
        }
        else if (phase == LIBRDP_LIFECYCLE_ACTIVE)
        {
            active_count++;
            if (active_count == 1u)
                first_active = index;
            else if (active_count == 2u)
                second_active = index;
        }
        else if (phase == LIBRDP_LIFECYCLE_DISCONNECTING)
            disconnecting_count++;
        else if (phase == LIBRDP_LIFECYCLE_DISCONNECTED)
        {
            disconnected_count++;
            if (disconnected_count == 1u)
                first_disconnected = index;
            else if (disconnected_count == 2u)
                final_disconnected = index;
        }
        else if (phase == LIBRDP_LIFECYCLE_RECONNECTING)
        {
            if (reconnecting != SIZE_MAX)
                return 0;
            reconnecting = index;
        }
    }
    return connecting_count == 2u && active_count == 2u &&
           disconnecting_count == 2u &&
           disconnected_count == 2u &&
           first_active < first_disconnected &&
           first_disconnected < reconnecting &&
           reconnecting < second_connecting &&
           second_connecting < second_active &&
           second_active < final_disconnected &&
           final_disconnected + 1u == capture->lifecycle_count;
}

static librdp_status smoke_capture_start(
    void* context,
    const server_platform_capture_sink* sink)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (!platform || !sink || !sink->frame || !sink->lost)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    platform->capture_sink = *sink;
    return LIBRDP_STATUS_OK;
}

static void smoke_capture_stop(void* context)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (platform)
        memset(&platform->capture_sink, 0, sizeof(platform->capture_sink));
}

/*
 * Emit a complete deterministic frame synchronously. The host copies the
 * pixels before this callback returns, so no provider buffer escapes.
 */
static librdp_status smoke_capture_request(void* context)
{
    smoke_platform* platform = (smoke_platform*)context;
    server_platform_frame frame;
    unsigned int sequence = 0u;
    unsigned int variant = 0u;

    if (!platform || !platform->capture_sink.frame)
        return LIBRDP_STATUS_STATE;
    sequence = atomic_fetch_add_explicit(&platform->capture_requests,
                                         1u,
                                         memory_order_relaxed) +
               1u;
    memset(&frame, 0, sizeof(frame));
    frame.width = SMOKE_CAPTURE_WIDTH;
    frame.height = SMOKE_CAPTURE_HEIGHT;
    frame.stride = SMOKE_CAPTURE_WIDTH * 4u;
    variant = atomic_load_explicit(&platform->capture_variant,
                                   memory_order_acquire);
    frame.pixels = variant ? platform->alternate_pixels :
                             platform->pixels;
    frame.pixels_len = sizeof(platform->pixels);
    frame.sequence = sequence;
    frame.timestamp_ns = smoke_now_ns();
    platform->capture_sink.frame(&frame,
                                 platform->capture_sink.user_data);
    return LIBRDP_STATUS_OK;
}

static librdp_status smoke_input_inject(
    void* context,
    const librdp_server_input_event* event)
{
    smoke_platform* platform = (smoke_platform*)context;
    int valid = 0;

    if (!platform || !event)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (event->type == LIBRDP_SERVER_INPUT_SCANCODE_KEY)
    {
        valid = event->param1 == 0x1eu &&
                (event->flags == 0u || event->flags == 0x8000u);
        atomic_fetch_add_explicit(&platform->key_events,
                                  1u,
                                  memory_order_relaxed);
    }
    else if (event->type == LIBRDP_SERVER_INPUT_UNICODE_KEY)
    {
        valid = event->param1 == 0x00e9u &&
                (event->flags == 0u || event->flags == 0x8000u);
        atomic_fetch_add_explicit(&platform->unicode_events,
                                  1u,
                                  memory_order_relaxed);
    }
    else if (event->type == LIBRDP_SERVER_INPUT_MOUSE)
    {
        valid = event->flags == 0x0800u && event->x == 7u && event->y == 9u;
        atomic_fetch_add_explicit(&platform->mouse_events,
                                  1u,
                                  memory_order_relaxed);
    }
    else if (event->type == LIBRDP_SERVER_INPUT_EXTENDED_MOUSE)
    {
        valid = (event->flags == 0x8001u || event->flags == 0x0001u) &&
                event->x == 11u && event->y == 13u;
        atomic_fetch_add_explicit(&platform->extended_mouse_events,
                                  1u,
                                  memory_order_relaxed);
    }
    if (!valid)
    {
        atomic_fetch_add_explicit(&platform->input_validation_errors,
                                  1u,
                                  memory_order_relaxed);
    }
    return LIBRDP_STATUS_OK;
}

static void smoke_input_release(void* context)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (platform)
    {
        atomic_fetch_add_explicit(&platform->releases,
                                  1u,
                                  memory_order_relaxed);
    }
}

static void smoke_drive_fail(smoke_platform* platform,
                             librdp_status status,
                             uint32_t io_status)
{
    if (!platform)
        return;
    platform->drive_failure_status = status;
    platform->drive_failure_io_status = io_status;
    atomic_store_explicit(&platform->drive_stage,
                          SMOKE_DRIVE_STAGE_FAILED,
                          memory_order_release);
}

static void smoke_drive_write_u32_le(uint8_t* destination, uint32_t value)
{
    if (!destination)
        return;
    destination[0] = (uint8_t)(value & 0xffu);
    destination[1] = (uint8_t)((value >> 8u) & 0xffu);
    destination[2] = (uint8_t)((value >> 16u) & 0xffu);
    destination[3] = (uint8_t)((value >> 24u) & 0xffu);
}

static void smoke_drive_write_u64_le(uint8_t* destination, uint64_t value)
{
    if (!destination)
        return;
    smoke_drive_write_u32_le(destination, (uint32_t)(value & UINT64_C(0xffffffff)));
    smoke_drive_write_u32_le(destination + 4u, (uint32_t)(value >> 32u));
}

static uint32_t smoke_drive_read_u32_le(const uint8_t* source)
{
    if (!source)
        return 0u;
    return (uint32_t)source[0] |
           ((uint32_t)source[1] << 8u) |
           ((uint32_t)source[2] << 16u) |
           ((uint32_t)source[3] << 24u);
}

static uint64_t smoke_drive_read_u64_le(const uint8_t* source)
{
    if (!source)
        return 0u;
    return (uint64_t)smoke_drive_read_u32_le(source) |
           ((uint64_t)smoke_drive_read_u32_le(source + 4u)
            << 32u);
}

static size_t smoke_drive_make_rename_payload(const char* name,
                                              uint8_t* payload,
                                              size_t capacity)
{
    size_t name_len = name ? strlen(name) : 0u;
    size_t encoded_len = name_len * 2u;
    size_t index = 0u;

    if (!name || !payload || name_len == 0u ||
        name_len > (SIZE_MAX - 6u) / 2u ||
        encoded_len > UINT32_MAX || capacity < 6u + encoded_len)
        return 0u;
    memset(payload, 0, 6u + encoded_len);
    smoke_drive_write_u32_le(payload + 2u, (uint32_t)encoded_len);
    for (index = 0u; index < name_len; index++)
        payload[6u + index * 2u] = (uint8_t)name[index];
    return 6u + encoded_len;
}

static void smoke_drive_submit_request(
    smoke_platform* platform,
    smoke_drive_stage stage,
    const librdp_server_drive_request* operation)
{
    server_platform_drive_request request;

    if (!platform || !operation || !platform->drive_sink.request ||
        platform->drive_volume.volume_id == 0u)
    {
        smoke_drive_fail(platform, LIBRDP_STATUS_STATE, 0u);
        return;
    }
    memset(&request, 0, sizeof(request));
    request.request_id = ++platform->drive_next_request_id;
    request.volume_id = platform->drive_volume.volume_id;
    request.peer_id = platform->drive_volume.peer_id;
    request.generation = platform->drive_volume.generation;
    request.operation = *operation;
    atomic_store_explicit(&platform->drive_stage,
                          (unsigned int)stage,
                          memory_order_release);
    platform->drive_sink.request(&request,
                                 platform->drive_sink.user_data);
}

static void smoke_drive_submit(smoke_platform* platform,
                               smoke_drive_stage stage,
                               librdp_server_drive_operation operation,
                               librdp_server_drive_file_handle file,
                               const char* path,
                               const uint8_t* data,
                               size_t data_len,
                               uint32_t information_class,
                               uint64_t offset,
                               uint32_t length,
                               uint32_t create_disposition,
                               uint32_t create_options)
{
    librdp_server_drive_request request;

    if (!platform)
        return;
    memset(&request, 0, sizeof(request));
    if (librdp_server_drive_request_init(&request) !=
        LIBRDP_STATUS_OK)
    {
        smoke_drive_fail(platform,
                         LIBRDP_STATUS_STATE,
                         0u);
        return;
    }
    request.operation = operation;
    request.device = platform->drive_volume.device;
    request.file = file;
    request.path = path;
    request.data = data;
    request.data_len = data_len;
    request.information_class = information_class;
    request.offset = offset;
    request.length = length;
    request.desired_access =
        SMOKE_DRIVE_GENERIC_READ |
        (platform->drive_profile &&
                 (platform->drive_profile->mode ==
                      SMOKE_DRIVE_WRITABLE ||
                  platform->drive_profile->mode ==
                      SMOKE_DRIVE_LOCKING ||
                  platform->drive_profile->mode ==
                      SMOKE_DRIVE_METADATA ||
                  platform->drive_profile->mode ==
                      SMOKE_DRIVE_CONFINEMENT ||
                  platform->drive_profile->mode ==
                      SMOKE_DRIVE_LIMITS)
             ? SMOKE_DRIVE_GENERIC_WRITE
             : 0u);
    request.shared_access = SMOKE_DRIVE_SHARE_ALL;
    request.create_disposition = create_disposition;
    request.create_options = create_options;
    smoke_drive_submit_request(platform, stage, &request);
}

static void smoke_drive_submit_query(
    smoke_platform* platform,
    smoke_drive_stage stage,
    librdp_server_drive_operation operation,
    librdp_server_drive_file_handle file,
    const char* path,
    uint32_t information_class,
    uint8_t initial_query,
    uint32_t security_information)
{
    librdp_server_drive_request request;

    if (!platform)
        return;
    memset(&request, 0, sizeof(request));
    if (librdp_server_drive_request_init(&request) !=
        LIBRDP_STATUS_OK)
    {
        smoke_drive_fail(platform, LIBRDP_STATUS_STATE, 0u);
        return;
    }
    request.operation = operation;
    request.device = platform->drive_volume.device;
    request.file = file;
    request.path = path;
    request.information_class = information_class;
    request.initial_query = initial_query;
    request.security_information = security_information;
    request.output_buffer_length =
        operation == LIBRDP_SERVER_DRIVE_QUERY_SECURITY ? 4096u : 0u;
    smoke_drive_submit_request(platform, stage, &request);
}

static void smoke_drive_submit_lock(
    smoke_platform* platform,
    smoke_drive_stage stage,
    librdp_server_drive_file_handle file,
    librdp_server_drive_lock_operation operation)
{
    librdp_server_drive_request request;
    librdp_server_drive_lock_range range;

    if (!platform)
        return;
    memset(&request, 0, sizeof(request));
    memset(&range, 0, sizeof(range));
    if (librdp_server_drive_request_init(&request) !=
        LIBRDP_STATUS_OK)
    {
        smoke_drive_fail(platform, LIBRDP_STATUS_STATE, 0u);
        return;
    }
    range.offset = 0u;
    range.length = 8u;
    request.operation = LIBRDP_SERVER_DRIVE_LOCK;
    request.device = platform->drive_volume.device;
    request.file = file;
    request.lock_operation = operation;
    request.locks = &range;
    request.lock_count = 1u;
    smoke_drive_submit_request(platform, stage, &request);
}

static void smoke_drive_submit_notify(
    smoke_platform* platform,
    smoke_drive_stage stage,
    librdp_server_drive_file_handle file,
    uint32_t completion_filter)
{
    librdp_server_drive_request request;

    if (!platform)
        return;
    memset(&request, 0, sizeof(request));
    if (librdp_server_drive_request_init(&request) !=
        LIBRDP_STATUS_OK)
    {
        smoke_drive_fail(platform, LIBRDP_STATUS_STATE, 0u);
        return;
    }
    request.operation = LIBRDP_SERVER_DRIVE_NOTIFY_DIRECTORY;
    request.file = file;
    request.watch_tree = 1u;
    request.completion_filter = completion_filter;
    smoke_drive_submit_request(platform, stage, &request);
}

static void smoke_drive_submit_control(
    smoke_platform* platform,
    smoke_drive_stage stage,
    librdp_server_drive_file_handle file,
    uint32_t control_code,
    uint32_t output_buffer_length,
    const uint8_t* data,
    size_t data_len)
{
    librdp_server_drive_request request;

    if (!platform)
        return;
    memset(&request, 0, sizeof(request));
    if (librdp_server_drive_request_init(&request) !=
        LIBRDP_STATUS_OK)
    {
        smoke_drive_fail(platform, LIBRDP_STATUS_STATE, 0u);
        return;
    }
    request.operation = LIBRDP_SERVER_DRIVE_CONTROL;
    request.file = file;
    request.control_code = control_code;
    request.output_buffer_length = output_buffer_length;
    request.data = data;
    request.data_len = data_len;
    smoke_drive_submit_request(platform, stage, &request);
}

static void smoke_drive_submit_security_mode(
    smoke_platform* platform,
    smoke_drive_stage stage,
    librdp_server_drive_file_handle file,
    uint32_t mode)
{
    librdp_server_drive_request request;
    rdp_buffer descriptor;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!platform)
        return;
    memset(&request, 0, sizeof(request));
    rdp_buffer_init(&descriptor);
    status = librdp_server_drive_request_init(&request);
    if (status == LIBRDP_STATUS_OK)
    {
        status =
            rdp_filesystem_redirection_write_posix_security_descriptor(
                &descriptor,
                RDP_FILESYSTEM_REDIRECTION_DACL_SECURITY_INFORMATION,
                0u,
                0u,
                mode);
    }
    if (status != LIBRDP_STATUS_OK)
    {
        rdp_buffer_free(&descriptor);
        smoke_drive_fail(platform, status, 0u);
        return;
    }
    request.operation = LIBRDP_SERVER_DRIVE_SET_SECURITY;
    request.file = file;
    request.security_information =
        RDP_FILESYSTEM_REDIRECTION_DACL_SECURITY_INFORMATION;
    request.data = descriptor.data;
    request.data_len = descriptor.length;
    smoke_drive_submit_request(platform, stage, &request);
    rdp_buffer_free(&descriptor);
}

static librdp_status smoke_drive_start(
    void* context,
    const server_platform_drive_sink* sink)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (!platform || !sink || !sink->request || !sink->cancel)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    platform->drive_sink = *sink;
    return LIBRDP_STATUS_OK;
}

static void smoke_drive_stop(void* context)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (platform)
        memset(&platform->drive_sink, 0, sizeof(platform->drive_sink));
}

static librdp_status smoke_drive_present(
    void* context,
    const server_platform_drive_volume* volume)
{
    smoke_platform* platform = (smoke_platform*)context;
    int length = 0;

    if (!platform || !volume || !volume->name)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    length = snprintf(platform->drive_name,
                      sizeof(platform->drive_name),
                      "%s",
                      volume->name);
    if (length < 0 || (size_t)length >= sizeof(platform->drive_name))
        return LIBRDP_STATUS_LIMIT_EXCEEDED;
    platform->drive_volume = *volume;
    platform->drive_volume.name = platform->drive_name;
    {
        unsigned int presentation =
            atomic_fetch_add_explicit(&platform->drive_presentations,
                                      1u,
                                      memory_order_release) +
            1u;

        if (platform->drive_profile &&
            platform->drive_profile->mode == SMOKE_DRIVE_NOTIFY)
        {
            if (presentation == 1u)
            {
                platform->drive_previous_generation =
                    volume->generation;
                smoke_drive_submit(
                    platform,
                    SMOKE_DRIVE_STAGE_OPEN_NOTIFY_DIRECTORY,
                    LIBRDP_SERVER_DRIVE_CREATE,
                    (librdp_server_drive_file_handle){0},
                    "",
                    NULL,
                    0u,
                    0u,
                    0u,
                    0u,
                    SMOKE_DRIVE_OPEN_EXISTING,
                    SMOKE_DRIVE_DIRECTORY_OPTION);
            }
            else if (presentation == 2u &&
                     platform->drive_previous_generation !=
                         volume->generation)
            {
                smoke_drive_submit_query(
                    platform,
                    SMOKE_DRIVE_STAGE_NOTIFY_STALE_HANDLE,
                    LIBRDP_SERVER_DRIVE_QUERY_INFORMATION,
                    platform->drive_directory,
                    NULL,
                    RDP_SESSION_FILE_BASIC_INFORMATION,
                    0u,
                    0u);
            }
            else
            {
                smoke_drive_fail(platform,
                                 LIBRDP_STATUS_PROTOCOL_ERROR,
                                 0u);
            }
            return LIBRDP_STATUS_OK;
        }
    }
    if (platform->drive_profile)
    {
        if (platform->drive_profile->mode ==
            SMOKE_DRIVE_CONFINEMENT)
        {
            smoke_drive_submit(
                platform,
                SMOKE_DRIVE_STAGE_REJECT_TRAVERSAL,
                LIBRDP_SERVER_DRIVE_CREATE,
                (librdp_server_drive_file_handle){0},
                "../outside.txt",
                NULL,
                0u,
                0u,
                0u,
                0u,
                SMOKE_DRIVE_OPEN_EXISTING,
                0u);
            return LIBRDP_STATUS_OK;
        }
        if (platform->drive_profile->mode ==
            SMOKE_DRIVE_DEVICE_NODE)
        {
            smoke_drive_submit(
                platform,
                SMOKE_DRIVE_STAGE_REJECT_DEVICE_NODE,
                LIBRDP_SERVER_DRIVE_CREATE,
                (librdp_server_drive_file_handle){0},
                "null",
                NULL,
                0u,
                0u,
                0u,
                0u,
                SMOKE_DRIVE_OPEN_EXISTING,
                0u);
            return LIBRDP_STATUS_OK;
        }
        if (platform->drive_profile->mode ==
            SMOKE_DRIVE_LIMITS)
        {
            smoke_drive_submit(
                platform,
                SMOKE_DRIVE_STAGE_OPEN_LIMIT_PRIMARY,
                LIBRDP_SERVER_DRIVE_CREATE,
                (librdp_server_drive_file_handle){0},
                "limit-a.bin",
                NULL,
                0u,
                0u,
                0u,
                0u,
                SMOKE_DRIVE_CREATE_NEW,
                0u);
            return LIBRDP_STATUS_OK;
        }
        if (platform->drive_profile->mode ==
            SMOKE_DRIVE_ENUMERATION)
        {
            smoke_drive_submit(
                platform,
                SMOKE_DRIVE_STAGE_OPEN_ENUMERATION_DIRECTORY,
                LIBRDP_SERVER_DRIVE_CREATE,
                (librdp_server_drive_file_handle){0},
                "",
                NULL,
                0u,
                0u,
                0u,
                0u,
                SMOKE_DRIVE_OPEN_EXISTING,
                SMOKE_DRIVE_DIRECTORY_OPTION);
            return LIBRDP_STATUS_OK;
        }
        if (platform->drive_profile->mode ==
            SMOKE_DRIVE_LOCKING)
        {
            smoke_drive_submit(
                platform,
                SMOKE_DRIVE_STAGE_OPEN_LOCK_PRIMARY,
                LIBRDP_SERVER_DRIVE_CREATE,
                (librdp_server_drive_file_handle){0},
                "marker.txt",
                NULL,
                0u,
                0u,
                0u,
                0u,
                SMOKE_DRIVE_OPEN_EXISTING,
                0u);
            return LIBRDP_STATUS_OK;
        }
        if (platform->drive_profile->mode ==
            SMOKE_DRIVE_METADATA)
        {
            smoke_drive_submit(
                platform,
                SMOKE_DRIVE_STAGE_OPEN_METADATA_FILE,
                LIBRDP_SERVER_DRIVE_CREATE,
                (librdp_server_drive_file_handle){0},
                "marker.txt",
                NULL,
                0u,
                0u,
                0u,
                0u,
                SMOKE_DRIVE_OPEN_EXISTING,
                0u);
            return LIBRDP_STATUS_OK;
        }
        const char* path =
            platform->drive_profile->mode == SMOKE_DRIVE_WRITABLE
                ? "created.bin"
                : "marker.txt";
        uint32_t disposition =
            platform->drive_profile->mode == SMOKE_DRIVE_WRITABLE
                ? SMOKE_DRIVE_CREATE_NEW
                : SMOKE_DRIVE_OPEN_EXISTING;

        smoke_drive_submit(platform,
                           SMOKE_DRIVE_STAGE_OPEN_FILE,
                           LIBRDP_SERVER_DRIVE_CREATE,
                           (librdp_server_drive_file_handle){0},
                           path,
                           NULL,
                           0u,
                           0u,
                           0u,
                           0u,
                           disposition,
                           0u);
    }
    return LIBRDP_STATUS_OK;
}

static void smoke_drive_remove(void* context,
                               uint32_t peer_id,
                               uint32_t generation,
                               uint32_t device_id)
{
    (void)context;
    (void)peer_id;
    (void)generation;
    (void)device_id;
}

static void smoke_drive_remove_peer(void* context,
                                    uint32_t peer_id,
                                    uint32_t generation)
{
    smoke_platform* platform = (smoke_platform*)context;

    (void)peer_id;
    (void)generation;
    if (platform)
    {
        atomic_fetch_add_explicit(&platform->drive_removals,
                                  1u,
                                  memory_order_release);
    }
}

static int smoke_drive_validate_notify_payload(
    const server_platform_drive_completion* completion)
{
    static const char expected_name[] = "nested\\notify-first.txt";
    size_t expected_name_length =
        (sizeof(expected_name) - 1u) * 2u;
    size_t index = 0u;

    if (!completion || !completion->data ||
        completion->data_len != 12u + expected_name_length ||
        smoke_drive_read_u32_le(completion->data) != 0u ||
        smoke_drive_read_u32_le(completion->data + 4u) !=
            RDP_FILESYSTEM_REDIRECTION_NOTIFY_ACTION_ADDED ||
        smoke_drive_read_u32_le(completion->data + 8u) !=
            expected_name_length)
        return 0;
    for (index = 0u; index < sizeof(expected_name) - 1u; index++)
    {
        if (completion->data[12u + index * 2u] !=
                (uint8_t)expected_name[index] ||
            completion->data[13u + index * 2u] != 0u)
            return 0;
    }
    return 1;
}

static int smoke_drive_validate_directory_payload(
    const smoke_drive_information_case* test_case,
    const server_platform_drive_completion* completion)
{
    static const char expected_name[] = "marker.txt";
    const uint8_t* encoded_name = NULL;
    size_t expected_name_bytes =
        (sizeof(expected_name) - 1u) * 2u;
    size_t name_length_offset = 60u;
    size_t index = 0u;

    if (!test_case || !completion || !completion->data ||
        completion->data_len !=
            test_case->minimum_length + expected_name_bytes ||
        smoke_drive_read_u32_le(completion->data) != 0u)
        return 0;
    if (test_case->information_class ==
        RDP_SESSION_FILE_NAMES_INFORMATION)
        name_length_offset = 8u;
    if (name_length_offset + 4u > test_case->minimum_length ||
        smoke_drive_read_u32_le(
            completion->data + name_length_offset) !=
            expected_name_bytes)
        return 0;
    encoded_name =
        completion->data + test_case->minimum_length;
    for (index = 0u; index < sizeof(expected_name) - 1u; index++)
    {
        if (encoded_name[index * 2u] !=
                (uint8_t)expected_name[index] ||
            encoded_name[index * 2u + 1u] != 0u)
            return 0;
    }
    return 1;
}

/*
 * Exercise every filesystem information layout across the complete
 * server-provider, RDPDR wire, and client-drive path. Each completion is
 * validated before the next request is submitted so correlation or framing
 * drift cannot be hidden by later successful operations.
 */
static librdp_status smoke_drive_complete_information(
    smoke_platform* platform,
    smoke_drive_stage stage,
    librdp_server_drive_io_result io_result,
    const server_platform_drive_completion* completion)
{
    const smoke_drive_information_case* test_case = NULL;

    if (!platform || !completion)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (stage == SMOKE_DRIVE_STAGE_OPEN_FILE)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->file.file_id == 0u)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        platform->drive_file = completion->file;
        platform->drive_sequence_index = 0u;
        test_case = &smoke_drive_file_information_cases[0];
        smoke_drive_submit_query(
            platform,
            SMOKE_DRIVE_STAGE_QUERY_FILE_CLASSES,
            LIBRDP_SERVER_DRIVE_QUERY_INFORMATION,
            platform->drive_file,
            NULL,
            test_case->information_class,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_QUERY_FILE_CLASSES)
    {
        librdp_server_drive_metadata metadata;
        librdp_status metadata_status = LIBRDP_STATUS_OK;

        if (platform->drive_sequence_index >=
            sizeof(smoke_drive_file_information_cases) /
                sizeof(smoke_drive_file_information_cases[0]))
        {
            smoke_drive_fail(platform, LIBRDP_STATUS_STATE, 0u);
            return LIBRDP_STATUS_OK;
        }
        test_case = &smoke_drive_file_information_cases[
            platform->drive_sequence_index];
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_QUERY_INFORMATION ||
            completion->information_class !=
                test_case->information_class ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->transferred != completion->data_len ||
            completion->data_len < test_case->minimum_length ||
            (completion->data_len > 0u && !completion->data))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        if (test_case->information_class ==
            RDP_SESSION_FILE_ALL_INFORMATION)
        {
            memset(&metadata, 0, sizeof(metadata));
            metadata_status =
                librdp_server_drive_metadata_init(&metadata);
            if (metadata_status == LIBRDP_STATUS_OK)
            {
                metadata_status =
                    librdp_server_drive_decode_file_metadata(
                        test_case->information_class,
                        completion->data,
                        completion->data_len,
                        &metadata);
            }
            if (metadata_status != LIBRDP_STATUS_OK ||
                metadata.directory ||
                metadata.file_size !=
                    sizeof(smoke_drive_marker_data) - 1u)
            {
                smoke_drive_fail(platform,
                                 LIBRDP_STATUS_PROTOCOL_ERROR,
                                 completion->io_status);
                return LIBRDP_STATUS_OK;
            }
        }
        platform->drive_sequence_index++;
        if (platform->drive_sequence_index <
            sizeof(smoke_drive_file_information_cases) /
                sizeof(smoke_drive_file_information_cases[0]))
        {
            test_case = &smoke_drive_file_information_cases[
                platform->drive_sequence_index];
            smoke_drive_submit_query(
                platform,
                SMOKE_DRIVE_STAGE_QUERY_FILE_CLASSES,
                LIBRDP_SERVER_DRIVE_QUERY_INFORMATION,
                platform->drive_file,
                NULL,
                test_case->information_class,
                0u,
                0u);
        }
        else
        {
            platform->drive_sequence_index = 0u;
            test_case =
                &smoke_drive_volume_information_cases[0];
            smoke_drive_submit_query(
                platform,
                SMOKE_DRIVE_STAGE_QUERY_VOLUME_CLASSES,
                LIBRDP_SERVER_DRIVE_QUERY_VOLUME,
                platform->drive_file,
                NULL,
                test_case->information_class,
                0u,
                0u);
        }
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_QUERY_VOLUME_CLASSES)
    {
        if (platform->drive_sequence_index >=
            sizeof(smoke_drive_volume_information_cases) /
                sizeof(smoke_drive_volume_information_cases[0]))
        {
            smoke_drive_fail(platform, LIBRDP_STATUS_STATE, 0u);
            return LIBRDP_STATUS_OK;
        }
        test_case = &smoke_drive_volume_information_cases[
            platform->drive_sequence_index];
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_QUERY_VOLUME ||
            completion->information_class !=
                test_case->information_class ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->transferred != completion->data_len ||
            !completion->data ||
            completion->data_len < test_case->minimum_length)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        platform->drive_sequence_index++;
        if (platform->drive_sequence_index <
            sizeof(smoke_drive_volume_information_cases) /
                sizeof(smoke_drive_volume_information_cases[0]))
        {
            test_case = &smoke_drive_volume_information_cases[
                platform->drive_sequence_index];
            smoke_drive_submit_query(
                platform,
                SMOKE_DRIVE_STAGE_QUERY_VOLUME_CLASSES,
                LIBRDP_SERVER_DRIVE_QUERY_VOLUME,
                platform->drive_file,
                NULL,
                test_case->information_class,
                0u,
                0u);
        }
        else
        {
            platform->drive_sequence_index = 0u;
            smoke_drive_submit_query(
                platform,
                SMOKE_DRIVE_STAGE_QUERY_SECURITY_CLASSES,
                LIBRDP_SERVER_DRIVE_QUERY_SECURITY,
                platform->drive_file,
                NULL,
                0u,
                0u,
                smoke_drive_security_information_cases[0]);
        }
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_QUERY_SECURITY_CLASSES)
    {
        rdp_filesystem_redirection_posix_security security;
        uint32_t security_information = 0u;

        if (platform->drive_sequence_index >=
            sizeof(smoke_drive_security_information_cases) /
                sizeof(smoke_drive_security_information_cases[0]))
        {
            smoke_drive_fail(platform, LIBRDP_STATUS_STATE, 0u);
            return LIBRDP_STATUS_OK;
        }
        security_information =
            smoke_drive_security_information_cases[
                platform->drive_sequence_index];
        memset(&security, 0, sizeof(security));
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_QUERY_SECURITY ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->transferred != completion->data_len ||
            !completion->data ||
            rdp_filesystem_redirection_parse_posix_security_descriptor(
                completion->data,
                completion->data_len,
                security_information,
                &security) != LIBRDP_STATUS_OK)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        platform->drive_sequence_index++;
        if (platform->drive_sequence_index <
            sizeof(smoke_drive_security_information_cases) /
                sizeof(smoke_drive_security_information_cases[0]))
        {
            smoke_drive_submit_query(
                platform,
                SMOKE_DRIVE_STAGE_QUERY_SECURITY_CLASSES,
                LIBRDP_SERVER_DRIVE_QUERY_SECURITY,
                platform->drive_file,
                NULL,
                0u,
                0u,
                smoke_drive_security_information_cases[
                    platform->drive_sequence_index]);
        }
        else
        {
            platform->drive_sequence_index = 0u;
            smoke_drive_submit(
                platform,
                SMOKE_DRIVE_STAGE_OPEN_INFORMATION_DIRECTORY,
                LIBRDP_SERVER_DRIVE_CREATE,
                (librdp_server_drive_file_handle){0},
                "",
                NULL,
                0u,
                0u,
                0u,
                0u,
                SMOKE_DRIVE_OPEN_EXISTING,
                SMOKE_DRIVE_DIRECTORY_OPTION);
        }
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_OPEN_INFORMATION_DIRECTORY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->file.file_id == 0u)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        platform->drive_directory = completion->file;
        platform->drive_sequence_index = 0u;
        test_case =
            &smoke_drive_directory_information_cases[0];
        smoke_drive_submit_query(
            platform,
            SMOKE_DRIVE_STAGE_QUERY_DIRECTORY_CLASSES,
            LIBRDP_SERVER_DRIVE_QUERY_DIRECTORY,
            platform->drive_directory,
            "marker.txt",
            test_case->information_class,
            1u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_QUERY_DIRECTORY_CLASSES)
    {
        if (platform->drive_sequence_index >=
            sizeof(smoke_drive_directory_information_cases) /
                sizeof(smoke_drive_directory_information_cases[0]))
        {
            smoke_drive_fail(platform, LIBRDP_STATUS_STATE, 0u);
            return LIBRDP_STATUS_OK;
        }
        test_case = &smoke_drive_directory_information_cases[
            platform->drive_sequence_index];
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_QUERY_DIRECTORY ||
            completion->information_class !=
                test_case->information_class ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->transferred != completion->data_len ||
            !smoke_drive_validate_directory_payload(test_case,
                                                     completion))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        platform->drive_sequence_index++;
        if (platform->drive_sequence_index <
            sizeof(smoke_drive_directory_information_cases) /
                sizeof(smoke_drive_directory_information_cases[0]))
        {
            test_case = &smoke_drive_directory_information_cases[
                platform->drive_sequence_index];
            smoke_drive_submit_query(
                platform,
                SMOKE_DRIVE_STAGE_QUERY_DIRECTORY_CLASSES,
                LIBRDP_SERVER_DRIVE_QUERY_DIRECTORY,
                platform->drive_directory,
                "marker.txt",
                test_case->information_class,
                1u,
                0u);
        }
        else
        {
            smoke_drive_submit(
                platform,
                SMOKE_DRIVE_STAGE_CLOSE_INFORMATION_DIRECTORY,
                LIBRDP_SERVER_DRIVE_CLOSE,
                platform->drive_directory,
                NULL,
                NULL,
                0u,
                0u,
                0u,
                0u,
                0u,
                0u);
        }
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_CLOSE_INFORMATION_DIRECTORY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CLOSE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_CLOSE_INFORMATION_FILE,
            LIBRDP_SERVER_DRIVE_CLOSE,
            platform->drive_file,
            NULL,
            NULL,
            0u,
            0u,
            0u,
            0u,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_CLOSE_INFORMATION_FILE)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CLOSE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        atomic_store_explicit(&platform->drive_stage,
                              SMOKE_DRIVE_STAGE_COMPLETE,
                              memory_order_release);
        return LIBRDP_STATUS_OK;
    }
    smoke_drive_fail(platform,
                     LIBRDP_STATUS_PROTOCOL_ERROR,
                     completion->io_status);
    return LIBRDP_STATUS_OK;
}

static int smoke_drive_enumeration_match(
    const server_platform_drive_completion* completion,
    librdp_server_drive_io_result io_result)
{
    const smoke_drive_information_case* test_case =
        &smoke_drive_directory_information_cases[0];

    return completion &&
           completion->operation ==
               LIBRDP_SERVER_DRIVE_QUERY_DIRECTORY &&
           completion->information_class ==
               test_case->information_class &&
           io_result == LIBRDP_SERVER_DRIVE_IO_SUCCESS &&
           completion->transferred == completion->data_len &&
           smoke_drive_validate_directory_payload(test_case,
                                                  completion);
}

/*
 * Validate restart and wildcard semantics over one live redirected-directory
 * handle. Successful and empty results are interleaved so stale cursor or
 * stale pattern state fails at the exact request that retained it.
 */
static librdp_status smoke_drive_complete_enumeration(
    smoke_platform* platform,
    smoke_drive_stage stage,
    librdp_server_drive_io_result io_result,
    const server_platform_drive_completion* completion)
{
    uint32_t information_class =
        smoke_drive_directory_information_cases[0].information_class;

    if (!platform || !completion)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (stage == SMOKE_DRIVE_STAGE_OPEN_ENUMERATION_DIRECTORY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->file.file_id == 0u)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        platform->drive_directory = completion->file;
        smoke_drive_submit_query(
            platform,
            SMOKE_DRIVE_STAGE_QUERY_ENUMERATION_MATCH,
            LIBRDP_SERVER_DRIVE_QUERY_DIRECTORY,
            platform->drive_directory,
            "*.txt",
            information_class,
            1u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_QUERY_ENUMERATION_MATCH)
    {
        if (!smoke_drive_enumeration_match(completion, io_result))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit_query(
            platform,
            SMOKE_DRIVE_STAGE_QUERY_ENUMERATION_END,
            LIBRDP_SERVER_DRIVE_QUERY_DIRECTORY,
            platform->drive_directory,
            NULL,
            information_class,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_QUERY_ENUMERATION_END)
    {
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_QUERY_DIRECTORY ||
            completion->information_class != information_class ||
            io_result != LIBRDP_SERVER_DRIVE_IO_NO_MORE_FILES ||
            completion->data_len != 0u)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit_query(
            platform,
            SMOKE_DRIVE_STAGE_QUERY_ENUMERATION_RESTART,
            LIBRDP_SERVER_DRIVE_QUERY_DIRECTORY,
            platform->drive_directory,
            "*.txt",
            information_class,
            1u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_QUERY_ENUMERATION_RESTART)
    {
        if (!smoke_drive_enumeration_match(completion, io_result))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit_query(
            platform,
            SMOKE_DRIVE_STAGE_QUERY_ENUMERATION_MISS,
            LIBRDP_SERVER_DRIVE_QUERY_DIRECTORY,
            platform->drive_directory,
            "*.bin",
            information_class,
            1u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_QUERY_ENUMERATION_MISS)
    {
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_QUERY_DIRECTORY ||
            completion->information_class != information_class ||
            io_result != LIBRDP_SERVER_DRIVE_IO_NO_MORE_FILES ||
            completion->data_len != 0u)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit_query(
            platform,
            SMOKE_DRIVE_STAGE_QUERY_ENUMERATION_GLOB,
            LIBRDP_SERVER_DRIVE_QUERY_DIRECTORY,
            platform->drive_directory,
            "marker.?xt",
            information_class,
            1u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_QUERY_ENUMERATION_GLOB)
    {
        if (!smoke_drive_enumeration_match(completion, io_result))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_CLOSE_ENUMERATION_DIRECTORY,
            LIBRDP_SERVER_DRIVE_CLOSE,
            platform->drive_directory,
            NULL,
            NULL,
            0u,
            0u,
            0u,
            0u,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_CLOSE_ENUMERATION_DIRECTORY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CLOSE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        atomic_store_explicit(&platform->drive_stage,
                              SMOKE_DRIVE_STAGE_COMPLETE,
                              memory_order_release);
        return LIBRDP_STATUS_OK;
    }
    smoke_drive_fail(platform,
                     LIBRDP_STATUS_PROTOCOL_ERROR,
                     completion->io_status);
    return LIBRDP_STATUS_OK;
}

static int smoke_drive_lock_completed(
    const server_platform_drive_completion* completion,
    librdp_server_drive_io_result io_result)
{
    return completion &&
           completion->operation == LIBRDP_SERVER_DRIVE_LOCK &&
           io_result == LIBRDP_SERVER_DRIVE_IO_SUCCESS;
}

static int smoke_drive_lock_conflicted(
    const server_platform_drive_completion* completion)
{
    return completion &&
           completion->operation == LIBRDP_SERVER_DRIVE_LOCK &&
           completion->io_status ==
               RDP_SESSION_DEVICE_LOCK_NOT_GRANTED;
}

/*
 * Drive two independent remote handles through shared, conflicting exclusive,
 * unlock, and successful exclusive lock transitions. The sequence verifies
 * that client-side ownership metadata remains authoritative even where native
 * process-scoped locks would otherwise merge descriptors.
 */
static librdp_status smoke_drive_complete_locking(
    smoke_platform* platform,
    smoke_drive_stage stage,
    librdp_server_drive_io_result io_result,
    const server_platform_drive_completion* completion)
{
    if (!platform || !completion)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (stage == SMOKE_DRIVE_STAGE_OPEN_LOCK_PRIMARY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->file.file_id == 0u)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        platform->drive_file = completion->file;
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_OPEN_LOCK_SECONDARY,
            LIBRDP_SERVER_DRIVE_CREATE,
            (librdp_server_drive_file_handle){0},
            "marker.txt",
            NULL,
            0u,
            0u,
            0u,
            0u,
            SMOKE_DRIVE_OPEN_EXISTING,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_OPEN_LOCK_SECONDARY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->file.file_id == 0u ||
            completion->file.file_id ==
                platform->drive_file.file_id)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        platform->drive_secondary_file = completion->file;
        smoke_drive_submit_lock(
            platform,
            SMOKE_DRIVE_STAGE_LOCK_SHARED_PRIMARY,
            platform->drive_file,
            LIBRDP_SERVER_DRIVE_LOCK_SHARED);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_LOCK_SHARED_PRIMARY)
    {
        if (!smoke_drive_lock_completed(completion, io_result))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit_lock(
            platform,
            SMOKE_DRIVE_STAGE_LOCK_SHARED_SECONDARY,
            platform->drive_secondary_file,
            LIBRDP_SERVER_DRIVE_LOCK_SHARED);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_LOCK_SHARED_SECONDARY)
    {
        if (!smoke_drive_lock_completed(completion, io_result))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit_lock(
            platform,
            SMOKE_DRIVE_STAGE_LOCK_EXCLUSIVE_SAME_HANDLE,
            platform->drive_secondary_file,
            LIBRDP_SERVER_DRIVE_LOCK_EXCLUSIVE);
        return LIBRDP_STATUS_OK;
    }
    if (stage ==
        SMOKE_DRIVE_STAGE_LOCK_EXCLUSIVE_SAME_HANDLE)
    {
        if (!smoke_drive_lock_conflicted(completion))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit_lock(
            platform,
            SMOKE_DRIVE_STAGE_UNLOCK_SHARED_SECONDARY,
            platform->drive_secondary_file,
            LIBRDP_SERVER_DRIVE_UNLOCK);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_UNLOCK_SHARED_SECONDARY)
    {
        if (!smoke_drive_lock_completed(completion, io_result))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit_lock(
            platform,
            SMOKE_DRIVE_STAGE_LOCK_EXCLUSIVE_CONFLICT,
            platform->drive_secondary_file,
            LIBRDP_SERVER_DRIVE_LOCK_EXCLUSIVE);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_LOCK_EXCLUSIVE_CONFLICT)
    {
        if (!smoke_drive_lock_conflicted(completion))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit_lock(
            platform,
            SMOKE_DRIVE_STAGE_UNLOCK_SHARED_PRIMARY,
            platform->drive_file,
            LIBRDP_SERVER_DRIVE_UNLOCK);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_UNLOCK_SHARED_PRIMARY)
    {
        if (!smoke_drive_lock_completed(completion, io_result))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit_lock(
            platform,
            SMOKE_DRIVE_STAGE_LOCK_EXCLUSIVE_SECONDARY,
            platform->drive_secondary_file,
            LIBRDP_SERVER_DRIVE_LOCK_EXCLUSIVE);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_LOCK_EXCLUSIVE_SECONDARY)
    {
        if (!smoke_drive_lock_completed(completion, io_result))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit_lock(
            platform,
            SMOKE_DRIVE_STAGE_UNLOCK_EXCLUSIVE_SECONDARY,
            platform->drive_secondary_file,
            LIBRDP_SERVER_DRIVE_UNLOCK);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_UNLOCK_EXCLUSIVE_SECONDARY)
    {
        if (!smoke_drive_lock_completed(completion, io_result))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_CLOSE_LOCK_SECONDARY,
            LIBRDP_SERVER_DRIVE_CLOSE,
            platform->drive_secondary_file,
            NULL,
            NULL,
            0u,
            0u,
            0u,
            0u,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_CLOSE_LOCK_SECONDARY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CLOSE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_CLOSE_LOCK_PRIMARY,
            LIBRDP_SERVER_DRIVE_CLOSE,
            platform->drive_file,
            NULL,
            NULL,
            0u,
            0u,
            0u,
            0u,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_CLOSE_LOCK_PRIMARY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CLOSE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        atomic_store_explicit(&platform->drive_stage,
                              SMOKE_DRIVE_STAGE_COMPLETE,
                              memory_order_release);
        return LIBRDP_STATUS_OK;
    }
    smoke_drive_fail(platform,
                     LIBRDP_STATUS_PROTOCOL_ERROR,
                     completion->io_status);
    return LIBRDP_STATUS_OK;
}

/*
 * Verify directory change notification, local cancellation, suppression of the
 * resulting late wire completion, and stale-handle rejection after reconnect.
 */
static librdp_status smoke_drive_complete_notify(
    smoke_platform* platform,
    smoke_drive_stage stage,
    librdp_server_drive_io_result io_result,
    const server_platform_drive_completion* completion)
{
    if (!platform || !completion)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (completion->request_id != platform->drive_next_request_id)
    {
        smoke_drive_fail(platform,
                         LIBRDP_STATUS_PROTOCOL_ERROR,
                         completion->io_status);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_NOTIFY_CANCEL_PENDING)
    {
        if (completion->type !=
                LIBRDP_SERVER_DRIVE_REQUEST_CANCELLED ||
            completion->status != LIBRDP_STATUS_CANCELLED ||
            completion->operation !=
                LIBRDP_SERVER_DRIVE_NOTIFY_DIRECTORY)
        {
            smoke_drive_fail(platform,
                             completion->status,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        atomic_store_explicit(
            &platform->drive_stage,
            SMOKE_DRIVE_STAGE_NOTIFY_LATE_PENDING,
            memory_order_release);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_NOTIFY_STALE_HANDLE)
    {
        if (completion->type !=
                LIBRDP_SERVER_DRIVE_REQUEST_CANCELLED ||
            completion->status != LIBRDP_STATUS_STATE ||
            completion->operation !=
                LIBRDP_SERVER_DRIVE_QUERY_INFORMATION)
        {
            smoke_drive_fail(platform,
                             completion->status,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_OPEN_NOTIFY_RECONNECTED_DIRECTORY,
            LIBRDP_SERVER_DRIVE_CREATE,
            (librdp_server_drive_file_handle){0},
            "",
            NULL,
            0u,
            0u,
            0u,
            0u,
            SMOKE_DRIVE_OPEN_EXISTING,
            SMOKE_DRIVE_DIRECTORY_OPTION);
        return LIBRDP_STATUS_OK;
    }
    if (completion->type !=
            LIBRDP_SERVER_DRIVE_REQUEST_COMPLETED ||
        completion->status != LIBRDP_STATUS_OK)
    {
        smoke_drive_fail(platform,
                         completion->status,
                         completion->io_status);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_OPEN_NOTIFY_DIRECTORY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->file.file_id == 0u)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        platform->drive_directory = completion->file;
        smoke_drive_submit_notify(
            platform,
            SMOKE_DRIVE_STAGE_NOTIFY_FIRST_PENDING,
            platform->drive_directory,
            RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_FILE_NAME |
                RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_DIRECTORY_NAME);
        return LIBRDP_STATUS_OK;
    }
    if (stage ==
        SMOKE_DRIVE_STAGE_NOTIFY_FIRST_WAIT_COMPLETION)
    {
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_NOTIFY_DIRECTORY ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            !smoke_drive_validate_notify_payload(completion))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit_notify(
            platform,
            SMOKE_DRIVE_STAGE_NOTIFY_CANCEL_PENDING,
            platform->drive_directory,
            RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_FILE_NAME |
                RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_DIRECTORY_NAME);
        if (!platform->drive_sink.cancel)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_STATE,
                             0u);
            return LIBRDP_STATUS_OK;
        }
        platform->drive_sink.cancel(
            platform->drive_volume.peer_id,
            platform->drive_volume.generation,
            platform->drive_next_request_id,
            platform->drive_sink.user_data);
        return LIBRDP_STATUS_OK;
    }
    if (stage ==
        SMOKE_DRIVE_STAGE_OPEN_NOTIFY_RECONNECTED_DIRECTORY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->file.file_id == 0u ||
            completion->file.reconnect_generation !=
                platform->drive_volume.device.reconnect_generation)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        platform->drive_file = completion->file;
        smoke_drive_submit_notify(
            platform,
            SMOKE_DRIVE_STAGE_NOTIFY_UNSUPPORTED_FILTER,
            platform->drive_file,
            RDP_FILESYSTEM_REDIRECTION_NOTIFY_STREAM_NAME);
        return LIBRDP_STATUS_OK;
    }
    if (stage ==
        SMOKE_DRIVE_STAGE_NOTIFY_UNSUPPORTED_FILTER)
    {
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_NOTIFY_DIRECTORY ||
            io_result != LIBRDP_SERVER_DRIVE_IO_UNSUPPORTED ||
            completion->data_len != 0u)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_CLOSE_NOTIFY_RECONNECTED_DIRECTORY,
            LIBRDP_SERVER_DRIVE_CLOSE,
            platform->drive_file,
            NULL,
            NULL,
            0u,
            0u,
            0u,
            0u,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage ==
        SMOKE_DRIVE_STAGE_CLOSE_NOTIFY_RECONNECTED_DIRECTORY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CLOSE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        atomic_store_explicit(&platform->drive_stage,
                              SMOKE_DRIVE_STAGE_COMPLETE,
                              memory_order_release);
        return LIBRDP_STATUS_OK;
    }
    smoke_drive_fail(platform,
                     LIBRDP_STATUS_PROTOCOL_ERROR,
                     completion->io_status);
    return LIBRDP_STATUS_OK;
}

static int smoke_drive_ea_contains(const uint8_t* data,
                                   size_t data_len,
                                   const char* expected_name,
                                   const uint8_t* expected_value,
                                   size_t expected_value_len)
{
    size_t offset = 0u;
    size_t expected_name_len =
        expected_name ? strlen(expected_name) : 0u;

    if (!data || data_len == 0u || !expected_name ||
        (!expected_value && expected_value_len > 0u) ||
        expected_name_len > UINT8_MAX ||
        expected_value_len > UINT16_MAX)
        return 0;
    while (offset < data_len)
    {
        uint32_t next = 0u;
        uint16_t value_len = 0u;
        uint8_t name_len = 0u;
        size_t minimum = 0u;
        size_t record_len = 0u;

        if (data_len - offset < 8u)
            return 0;
        next = smoke_drive_read_u32_le(data + offset);
        name_len = data[offset + 5u];
        value_len =
            (uint16_t)((uint16_t)data[offset + 6u] |
                       ((uint16_t)data[offset + 7u] << 8u));
        minimum = 8u + (size_t)name_len + 1u +
                  (size_t)value_len;
        record_len = next != 0u ? (size_t)next
                                : data_len - offset;
        if (record_len < minimum ||
            record_len > data_len - offset ||
            (next != 0u && (next & 3u) != 0u) ||
            data[offset + 8u + name_len] != 0u)
            return 0;
        if ((size_t)name_len == expected_name_len &&
            (size_t)value_len == expected_value_len &&
            memcmp(data + offset + 8u,
                   expected_name,
                   expected_name_len) == 0 &&
            (expected_value_len == 0u ||
             memcmp(data + offset + 9u + name_len,
                    expected_value,
                    expected_value_len) == 0))
            return 1;
        if (next == 0u)
            break;
        offset += next;
    }
    return 0;
}

static int smoke_drive_allocated_ranges_valid(const uint8_t* data,
                                              size_t data_len)
{
    uint64_t total = 0u;
    uint64_t file_size =
        SMOKE_DRIVE_LARGE_OFFSET + 1u;
    size_t offset = 0u;

    if (!data || data_len == 0u ||
        (data_len % 16u) != 0u)
        return 0;
    while (offset < data_len)
    {
        uint64_t range_offset =
            smoke_drive_read_u64_le(data + offset);
        uint64_t range_length =
            smoke_drive_read_u64_le(data + offset + 8u);

        if (range_length == 0u ||
            range_offset >= file_size ||
            range_length > file_size - range_offset ||
            total > UINT64_MAX - range_length)
            return 0;
        total += range_length;
        offset += 16u;
    }
    return total < file_size / 2u;
}

/*
 * Exercise filesystem metadata through the public server drive provider and
 * the complete RDPDR wire path. The sequence validates host-backed timestamps,
 * DOS attributes, extended attributes, POSIX DACL translation, sparse extents,
 * and offsets beyond the 32-bit file-size boundary.
 */
static librdp_status smoke_drive_complete_metadata(
    smoke_platform* platform,
    smoke_drive_stage stage,
    librdp_server_drive_io_result io_result,
    const server_platform_drive_completion* completion)
{
    static const uint8_t archive_value[] =
        "0x00000020";
    uint8_t payload[36];

    if (!platform || !completion)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(payload, 0, sizeof(payload));
    if (stage == SMOKE_DRIVE_STAGE_OPEN_METADATA_FILE)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->file.file_id == 0u)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        platform->drive_file = completion->file;
        smoke_drive_write_u64_le(payload + 8u,
                                 SMOKE_DRIVE_ACCESS_FILETIME);
        smoke_drive_write_u64_le(payload + 16u,
                                 SMOKE_DRIVE_WRITE_FILETIME);
        smoke_drive_write_u32_le(
            payload + 32u,
            RDP_SESSION_FILE_ATTRIBUTE_READONLY |
                RDP_SESSION_FILE_ATTRIBUTE_ARCHIVE);
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_SET_METADATA_BASIC,
            LIBRDP_SERVER_DRIVE_SET_INFORMATION,
            platform->drive_file,
            NULL,
            payload,
            sizeof(payload),
            RDP_SESSION_FILE_BASIC_INFORMATION,
            0u,
            0u,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_SET_METADATA_BASIC)
    {
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_SET_INFORMATION ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit_query(
            platform,
            SMOKE_DRIVE_STAGE_QUERY_METADATA_BASIC,
            LIBRDP_SERVER_DRIVE_QUERY_INFORMATION,
            platform->drive_file,
            NULL,
            RDP_SESSION_FILE_BASIC_INFORMATION,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_QUERY_METADATA_BASIC)
    {
        uint32_t attributes = 0u;

        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_QUERY_INFORMATION ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            !completion->data ||
            completion->data_len != 36u ||
            smoke_drive_read_u64_le(completion->data + 8u) !=
                SMOKE_DRIVE_ACCESS_FILETIME ||
            smoke_drive_read_u64_le(completion->data + 16u) !=
                SMOKE_DRIVE_WRITE_FILETIME)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        attributes =
            smoke_drive_read_u32_le(completion->data + 32u);
        if ((attributes &
             (RDP_SESSION_FILE_ATTRIBUTE_READONLY |
              RDP_SESSION_FILE_ATTRIBUTE_ARCHIVE)) !=
            (RDP_SESSION_FILE_ATTRIBUTE_READONLY |
             RDP_SESSION_FILE_ATTRIBUTE_ARCHIVE))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit_security_mode(
            platform,
            SMOKE_DRIVE_STAGE_SET_METADATA_SECURITY,
            platform->drive_file,
            SMOKE_DRIVE_METADATA_MODE);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_SET_METADATA_SECURITY)
    {
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_SET_SECURITY ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit_query(
            platform,
            SMOKE_DRIVE_STAGE_QUERY_METADATA_SECURITY,
            LIBRDP_SERVER_DRIVE_QUERY_SECURITY,
            platform->drive_file,
            NULL,
            0u,
            0u,
            RDP_FILESYSTEM_REDIRECTION_DACL_SECURITY_INFORMATION);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_QUERY_METADATA_SECURITY)
    {
        rdp_filesystem_redirection_posix_security security;

        memset(&security, 0, sizeof(security));
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_QUERY_SECURITY ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            !completion->data ||
            rdp_filesystem_redirection_parse_posix_security_descriptor(
                completion->data,
                completion->data_len,
                RDP_FILESYSTEM_REDIRECTION_DACL_SECURITY_INFORMATION,
                &security) != LIBRDP_STATUS_OK ||
            !security.mode_present ||
            (security.mode & 0777u) !=
                SMOKE_DRIVE_METADATA_MODE)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit_query(
            platform,
            SMOKE_DRIVE_STAGE_QUERY_METADATA_EA,
            LIBRDP_SERVER_DRIVE_QUERY_INFORMATION,
            platform->drive_file,
            NULL,
            RDP_SESSION_FILE_FULL_EA_INFORMATION,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_QUERY_METADATA_EA)
    {
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_QUERY_INFORMATION ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            !smoke_drive_ea_contains(
                completion->data,
                completion->data_len,
                SMOKE_DRIVE_METADATA_XATTR,
                smoke_drive_metadata_xattr,
                sizeof(smoke_drive_metadata_xattr) - 1u) ||
            !smoke_drive_ea_contains(
                completion->data,
                completion->data_len,
                SMOKE_DRIVE_DOS_ATTRIBUTES_XATTR,
                archive_value,
                sizeof(archive_value) - 1u))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        payload[0] = 1u;
        smoke_drive_submit_control(
            platform,
            SMOKE_DRIVE_STAGE_SET_METADATA_SPARSE,
            platform->drive_file,
            RDP_FILESYSTEM_REDIRECTION_FSCTL_SET_SPARSE,
            0u,
            payload,
            1u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_SET_METADATA_SPARSE)
    {
        static const uint8_t tail = 0x5au;

        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_CONTROL ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_WRITE_METADATA_LARGE,
            LIBRDP_SERVER_DRIVE_WRITE,
            platform->drive_file,
            NULL,
            &tail,
            1u,
            0u,
            SMOKE_DRIVE_LARGE_OFFSET,
            0u,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_WRITE_METADATA_LARGE)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_WRITE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->transferred != 1u)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit_query(
            platform,
            SMOKE_DRIVE_STAGE_QUERY_METADATA_ALL,
            LIBRDP_SERVER_DRIVE_QUERY_INFORMATION,
            platform->drive_file,
            NULL,
            RDP_SESSION_FILE_ALL_INFORMATION,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_QUERY_METADATA_ALL)
    {
        librdp_server_drive_metadata metadata;
        librdp_status metadata_status = LIBRDP_STATUS_OK;

        memset(&metadata, 0, sizeof(metadata));
        metadata_status = librdp_server_drive_metadata_init(&metadata);
        if (metadata_status == LIBRDP_STATUS_OK)
        {
            metadata_status = librdp_server_drive_decode_file_metadata(
                RDP_SESSION_FILE_ALL_INFORMATION,
                completion->data,
                completion->data_len,
                &metadata);
        }
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_QUERY_INFORMATION ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            metadata_status != LIBRDP_STATUS_OK ||
            metadata.file_size !=
                SMOKE_DRIVE_LARGE_OFFSET + 1u ||
            metadata.allocation_size >= metadata.file_size ||
            (metadata.attributes &
             RDP_SESSION_FILE_ATTRIBUTE_ARCHIVE) == 0u)
        {
            fprintf(stderr,
                    "drive metadata all mismatch decode=%s data_len=%zu "
                    "file_size=%llu allocation_size=%llu attributes=0x%08x\n",
                    librdp_status_name(metadata_status),
                    completion->data_len,
                    (unsigned long long)metadata.file_size,
                    (unsigned long long)metadata.allocation_size,
                    metadata.attributes);
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_write_u64_le(payload, 0u);
        smoke_drive_write_u64_le(
            payload + 8u,
            SMOKE_DRIVE_LARGE_OFFSET + 1u);
        smoke_drive_submit_control(
            platform,
            SMOKE_DRIVE_STAGE_QUERY_METADATA_RANGES,
            platform->drive_file,
            RDP_FILESYSTEM_REDIRECTION_FSCTL_QUERY_ALLOCATED_RANGES,
            4096u,
            payload,
            16u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_QUERY_METADATA_RANGES)
    {
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_CONTROL ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            !smoke_drive_allocated_ranges_valid(
                completion->data,
                completion->data_len))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_CLOSE_METADATA_FILE,
            LIBRDP_SERVER_DRIVE_CLOSE,
            platform->drive_file,
            NULL,
            NULL,
            0u,
            0u,
            0u,
            0u,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_CLOSE_METADATA_FILE)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CLOSE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        atomic_store_explicit(&platform->drive_stage,
                              SMOKE_DRIVE_STAGE_COMPLETE,
                              memory_order_release);
        return LIBRDP_STATUS_OK;
    }
    smoke_drive_fail(platform,
                     LIBRDP_STATUS_PROTOCOL_ERROR,
                     completion->io_status);
    return LIBRDP_STATUS_OK;
}

static int smoke_drive_confinement_path_rejected(
    librdp_server_drive_io_result io_result)
{
    return io_result == LIBRDP_SERVER_DRIVE_IO_NOT_FOUND ||
           io_result == LIBRDP_SERVER_DRIVE_IO_ACCESS_DENIED ||
           io_result == LIBRDP_SERVER_DRIVE_IO_UNSUPPORTED;
}

/*
 * Keep the hostile-path sequence strictly ordered. Traversal is rejected at
 * both the public application boundary and the counted rename PDU boundary.
 * The remaining requests cross the RDPDR wire before host postconditions are
 * checked.
 */
static librdp_status smoke_drive_complete_confinement(
    smoke_platform* platform,
    smoke_drive_stage stage,
    librdp_server_drive_io_result io_result,
    const server_platform_drive_completion* completion)
{
    smoke_drive_confinement_fixture* fixture = NULL;
    uint8_t rename_payload[512];
    size_t rename_len = 0u;

    if (!platform || !completion)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    fixture = platform->drive_confinement;
    if (!fixture)
    {
        smoke_drive_fail(platform, LIBRDP_STATUS_STATE, 0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_REJECT_TRAVERSAL)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            completion->type !=
                LIBRDP_SERVER_DRIVE_REQUEST_CANCELLED ||
            completion->status != LIBRDP_STATUS_STATE)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_REJECT_ABSOLUTE,
            LIBRDP_SERVER_DRIVE_CREATE,
            (librdp_server_drive_file_handle){0},
            fixture->outside_file,
            NULL,
            0u,
            0u,
            0u,
            0u,
            SMOKE_DRIVE_OPEN_EXISTING,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (completion->request_id != platform->drive_next_request_id ||
        completion->type != LIBRDP_SERVER_DRIVE_REQUEST_COMPLETED ||
        completion->status != LIBRDP_STATUS_OK)
    {
        smoke_drive_fail(platform,
                         completion->status,
                         completion->io_status);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_REJECT_ABSOLUTE)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_NOT_FOUND)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_REJECT_FINAL_SYMLINK,
            LIBRDP_SERVER_DRIVE_CREATE,
            (librdp_server_drive_file_handle){0},
            "outside-link",
            NULL,
            0u,
            0u,
            0u,
            0u,
            SMOKE_DRIVE_OPEN_EXISTING,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_REJECT_FINAL_SYMLINK)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            !smoke_drive_confinement_path_rejected(io_result))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_REJECT_DIRECTORY_SYMLINK,
            LIBRDP_SERVER_DRIVE_CREATE,
            (librdp_server_drive_file_handle){0},
            "outside-directory-link/outside.txt",
            NULL,
            0u,
            0u,
            0u,
            0u,
            SMOKE_DRIVE_OPEN_EXISTING,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_REJECT_DIRECTORY_SYMLINK)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            !smoke_drive_confinement_path_rejected(io_result))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_REJECT_FIFO,
            LIBRDP_SERVER_DRIVE_CREATE,
            (librdp_server_drive_file_handle){0},
            "pipe-node",
            NULL,
            0u,
            0u,
            0u,
            0u,
            SMOKE_DRIVE_OPEN_EXISTING,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_REJECT_FIFO)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_ACCESS_DENIED)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_REJECT_SOCKET,
            LIBRDP_SERVER_DRIVE_CREATE,
            (librdp_server_drive_file_handle){0},
            "socket-node",
            NULL,
            0u,
            0u,
            0u,
            0u,
            SMOKE_DRIVE_OPEN_EXISTING,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_REJECT_SOCKET)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            !smoke_drive_confinement_path_rejected(io_result))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_OPEN_RACE_FILE,
            LIBRDP_SERVER_DRIVE_CREATE,
            (librdp_server_drive_file_handle){0},
            "race.txt",
            NULL,
            0u,
            0u,
            0u,
            0u,
            SMOKE_DRIVE_OPEN_EXISTING,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_OPEN_RACE_FILE)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->file.file_id == 0u)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        platform->drive_file = completion->file;
        rename_len = smoke_drive_make_rename_payload(
            "../escaped.txt",
            rename_payload,
            sizeof(rename_payload));
        if (rename_len == 0u)
        {
            smoke_drive_fail(platform, LIBRDP_STATUS_STATE, 0u);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_REJECT_RENAME_TRAVERSAL,
            LIBRDP_SERVER_DRIVE_SET_INFORMATION,
            platform->drive_file,
            NULL,
            rename_payload,
            rename_len,
            SMOKE_DRIVE_FILE_RENAME_INFORMATION,
            0u,
            0u,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_REJECT_RENAME_TRAVERSAL)
    {
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_SET_INFORMATION ||
            io_result != LIBRDP_SERVER_DRIVE_IO_INVALID ||
            !smoke_drive_confinement_swap_race(fixture))
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        rename_len = smoke_drive_make_rename_payload(
            "race-renamed.txt",
            rename_payload,
            sizeof(rename_payload));
        if (rename_len == 0u)
        {
            smoke_drive_fail(platform, LIBRDP_STATUS_STATE, 0u);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_REJECT_RENAME_RACE,
            LIBRDP_SERVER_DRIVE_SET_INFORMATION,
            platform->drive_file,
            NULL,
            rename_payload,
            rename_len,
            SMOKE_DRIVE_FILE_RENAME_INFORMATION,
            0u,
            0u,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_REJECT_RENAME_RACE)
    {
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_SET_INFORMATION ||
            io_result != LIBRDP_SERVER_DRIVE_IO_ACCESS_DENIED)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(platform,
                           SMOKE_DRIVE_STAGE_CLOSE_RACE_FILE,
                           LIBRDP_SERVER_DRIVE_CLOSE,
                           platform->drive_file,
                           NULL,
                           NULL,
                           0u,
                           0u,
                           0u,
                           0u,
                           0u,
                           0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_CLOSE_RACE_FILE)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CLOSE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        atomic_store_explicit(&platform->drive_stage,
                              SMOKE_DRIVE_STAGE_COMPLETE,
                              memory_order_release);
        return LIBRDP_STATUS_OK;
    }
    smoke_drive_fail(platform,
                     LIBRDP_STATUS_PROTOCOL_ERROR,
                     completion->io_status);
    return LIBRDP_STATUS_OK;
}

static librdp_status smoke_drive_complete_device_node(
    smoke_platform* platform,
    smoke_drive_stage stage,
    librdp_server_drive_io_result io_result,
    const server_platform_drive_completion* completion)
{
    if (!platform || !completion)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (stage != SMOKE_DRIVE_STAGE_REJECT_DEVICE_NODE ||
        completion->request_id != platform->drive_next_request_id ||
        completion->type != LIBRDP_SERVER_DRIVE_REQUEST_COMPLETED ||
        completion->status != LIBRDP_STATUS_OK ||
        completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
        io_result != LIBRDP_SERVER_DRIVE_IO_ACCESS_DENIED)
    {
        smoke_drive_fail(platform,
                         LIBRDP_STATUS_PROTOCOL_ERROR,
                         completion->io_status);
        return LIBRDP_STATUS_OK;
    }
    atomic_store_explicit(&platform->drive_stage,
                          SMOKE_DRIVE_STAGE_COMPLETE,
                          memory_order_release);
    return LIBRDP_STATUS_OK;
}

static librdp_status smoke_drive_complete_limits_invalid(
    smoke_platform* platform,
    const server_platform_drive_completion* completion)
{
    smoke_drive_fail(platform,
                     LIBRDP_STATUS_PROTOCOL_ERROR,
                     completion ? completion->io_status : 0u);
    return LIBRDP_STATUS_OK;
}

/*
 * Cross every redirected-drive resource cap through real protocol requests.
 * Pending notify identifiers are retained separately because their terminal
 * cancellation callbacks are intentionally delivered out of submission order.
 */
static librdp_status smoke_drive_complete_limits(
    smoke_platform* platform,
    smoke_drive_stage stage,
    librdp_server_drive_io_result io_result,
    const server_platform_drive_completion* completion)
{
    uint64_t expected_request_id = 0u;
    uint8_t size_payload[8] = {0};

    if (!platform || !completion)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    expected_request_id = platform->drive_next_request_id;
    if (stage ==
        SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_CANCEL_FIRST_PENDING)
        expected_request_id = platform->drive_pending_request_ids[0];
    else if (stage ==
             SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_CANCEL_SECOND_PENDING)
        expected_request_id = platform->drive_pending_request_ids[1];
    if (completion->request_id != expected_request_id)
    {
        smoke_drive_fail(platform,
                         LIBRDP_STATUS_PROTOCOL_ERROR,
                         completion->io_status);
        return LIBRDP_STATUS_OK;
    }
    if (stage ==
            SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_CANCEL_FIRST_PENDING ||
        stage ==
            SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_CANCEL_SECOND_PENDING)
    {
        if (completion->type !=
                LIBRDP_SERVER_DRIVE_REQUEST_CANCELLED ||
            completion->status != LIBRDP_STATUS_CANCELLED ||
            completion->operation !=
                LIBRDP_SERVER_DRIVE_NOTIFY_DIRECTORY)
        {
            smoke_drive_fail(platform,
                             completion->status,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        if (stage ==
            SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_CANCEL_FIRST_PENDING)
        {
            atomic_store_explicit(
                &platform->drive_stage,
                SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_WAIT_CANCEL_SECOND,
                memory_order_release);
        }
        else
        {
            smoke_drive_submit(
                platform,
                SMOKE_DRIVE_STAGE_CLOSE_LIMIT_DIRECTORY_TERTIARY,
                LIBRDP_SERVER_DRIVE_CLOSE,
                platform->drive_directory,
                NULL,
                NULL,
                0u,
                0u,
                0u,
                0u,
                0u,
                0u);
        }
        return LIBRDP_STATUS_OK;
    }
    if (completion->type !=
            LIBRDP_SERVER_DRIVE_REQUEST_COMPLETED ||
        completion->status != LIBRDP_STATUS_OK)
    {
        smoke_drive_fail(platform,
                         completion->status,
                         completion->io_status);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_OPEN_LIMIT_PRIMARY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->file.file_id == 0u)
            return smoke_drive_complete_limits_invalid(platform, completion);
        platform->drive_file = completion->file;
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_OPEN_LIMIT_SECONDARY,
            LIBRDP_SERVER_DRIVE_CREATE,
            (librdp_server_drive_file_handle){0},
            "limit-b.bin",
            NULL,
            0u,
            0u,
            0u,
            0u,
            SMOKE_DRIVE_CREATE_NEW,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_OPEN_LIMIT_SECONDARY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->file.file_id == 0u)
            return smoke_drive_complete_limits_invalid(platform, completion);
        platform->drive_secondary_file = completion->file;
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_OPEN_LIMIT_TERTIARY,
            LIBRDP_SERVER_DRIVE_CREATE,
            (librdp_server_drive_file_handle){0},
            "limit-c.bin",
            NULL,
            0u,
            0u,
            0u,
            0u,
            SMOKE_DRIVE_CREATE_NEW,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_OPEN_LIMIT_TERTIARY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->file.file_id == 0u)
            return smoke_drive_complete_limits_invalid(platform, completion);
        platform->drive_directory = completion->file;
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_REJECT_LIMIT_QUATERNARY,
            LIBRDP_SERVER_DRIVE_CREATE,
            (librdp_server_drive_file_handle){0},
            "limit-d.bin",
            NULL,
            0u,
            0u,
            0u,
            0u,
            SMOKE_DRIVE_CREATE_NEW,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage ==
        SMOKE_DRIVE_STAGE_REJECT_LIMIT_QUATERNARY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_RESOURCE_LIMIT ||
            completion->file.file_id != 0u)
            return smoke_drive_complete_limits_invalid(platform, completion);
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_WRITE_LIMIT_VALID,
            LIBRDP_SERVER_DRIVE_WRITE,
            platform->drive_file,
            NULL,
            smoke_drive_limit_valid_data,
            sizeof(smoke_drive_limit_valid_data),
            0u,
            0u,
            (uint32_t)sizeof(smoke_drive_limit_valid_data),
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_WRITE_LIMIT_VALID)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_WRITE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->transferred !=
                sizeof(smoke_drive_limit_valid_data))
            return smoke_drive_complete_limits_invalid(platform, completion);
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_REJECT_LIMIT_WRITE_BYTES,
            LIBRDP_SERVER_DRIVE_WRITE,
            platform->drive_file,
            NULL,
            smoke_drive_limit_oversized_data,
            sizeof(smoke_drive_limit_oversized_data),
            0u,
            0u,
            (uint32_t)sizeof(smoke_drive_limit_oversized_data),
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage ==
        SMOKE_DRIVE_STAGE_REJECT_LIMIT_WRITE_BYTES)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_WRITE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_INVALID ||
            completion->transferred != 0u)
            return smoke_drive_complete_limits_invalid(platform, completion);
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_REJECT_LIMIT_WRITE_SIZE,
            LIBRDP_SERVER_DRIVE_WRITE,
            platform->drive_file,
            NULL,
            smoke_drive_limit_valid_data,
            sizeof(smoke_drive_limit_valid_data),
            0u,
            4u,
            (uint32_t)sizeof(smoke_drive_limit_valid_data),
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage ==
        SMOKE_DRIVE_STAGE_REJECT_LIMIT_WRITE_SIZE)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_WRITE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_ACCESS_DENIED ||
            completion->transferred != 0u)
            return smoke_drive_complete_limits_invalid(platform, completion);
        smoke_drive_write_u64_le(size_payload, 7u);
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_REJECT_LIMIT_SET_SIZE,
            LIBRDP_SERVER_DRIVE_SET_INFORMATION,
            platform->drive_file,
            NULL,
            size_payload,
            sizeof(size_payload),
            SMOKE_DRIVE_FILE_END_OF_FILE_INFORMATION,
            0u,
            0u,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage ==
        SMOKE_DRIVE_STAGE_REJECT_LIMIT_SET_SIZE)
    {
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_SET_INFORMATION ||
            io_result != LIBRDP_SERVER_DRIVE_IO_ACCESS_DENIED)
            return smoke_drive_complete_limits_invalid(platform, completion);
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_REJECT_LIMIT_READ_BYTES,
            LIBRDP_SERVER_DRIVE_READ,
            platform->drive_file,
            NULL,
            NULL,
            0u,
            0u,
            0u,
            (uint32_t)sizeof(smoke_drive_limit_oversized_data),
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage ==
        SMOKE_DRIVE_STAGE_REJECT_LIMIT_READ_BYTES)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_READ ||
            io_result != LIBRDP_SERVER_DRIVE_IO_INVALID ||
            completion->data_len != 0u)
            return smoke_drive_complete_limits_invalid(platform, completion);
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_CLOSE_LIMIT_TERTIARY,
            LIBRDP_SERVER_DRIVE_CLOSE,
            platform->drive_directory,
            NULL,
            NULL,
            0u,
            0u,
            0u,
            0u,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_CLOSE_LIMIT_TERTIARY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CLOSE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
            return smoke_drive_complete_limits_invalid(platform, completion);
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_CLOSE_LIMIT_SECONDARY,
            LIBRDP_SERVER_DRIVE_CLOSE,
            platform->drive_secondary_file,
            NULL,
            NULL,
            0u,
            0u,
            0u,
            0u,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_CLOSE_LIMIT_SECONDARY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CLOSE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
            return smoke_drive_complete_limits_invalid(platform, completion);
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_CLOSE_LIMIT_PRIMARY,
            LIBRDP_SERVER_DRIVE_CLOSE,
            platform->drive_file,
            NULL,
            NULL,
            0u,
            0u,
            0u,
            0u,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_CLOSE_LIMIT_PRIMARY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CLOSE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
            return smoke_drive_complete_limits_invalid(platform, completion);
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_OPEN_LIMIT_DIRECTORY_PRIMARY,
            LIBRDP_SERVER_DRIVE_CREATE,
            (librdp_server_drive_file_handle){0},
            "",
            NULL,
            0u,
            0u,
            0u,
            0u,
            SMOKE_DRIVE_OPEN_EXISTING,
            SMOKE_DRIVE_DIRECTORY_OPTION);
        return LIBRDP_STATUS_OK;
    }
    if (stage ==
        SMOKE_DRIVE_STAGE_OPEN_LIMIT_DIRECTORY_PRIMARY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->file.file_id == 0u)
            return smoke_drive_complete_limits_invalid(platform, completion);
        platform->drive_file = completion->file;
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_OPEN_LIMIT_DIRECTORY_SECONDARY,
            LIBRDP_SERVER_DRIVE_CREATE,
            (librdp_server_drive_file_handle){0},
            "",
            NULL,
            0u,
            0u,
            0u,
            0u,
            SMOKE_DRIVE_OPEN_EXISTING,
            SMOKE_DRIVE_DIRECTORY_OPTION);
        return LIBRDP_STATUS_OK;
    }
    if (stage ==
        SMOKE_DRIVE_STAGE_OPEN_LIMIT_DIRECTORY_SECONDARY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->file.file_id == 0u)
            return smoke_drive_complete_limits_invalid(platform, completion);
        platform->drive_secondary_file = completion->file;
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_OPEN_LIMIT_DIRECTORY_TERTIARY,
            LIBRDP_SERVER_DRIVE_CREATE,
            (librdp_server_drive_file_handle){0},
            "",
            NULL,
            0u,
            0u,
            0u,
            0u,
            SMOKE_DRIVE_OPEN_EXISTING,
            SMOKE_DRIVE_DIRECTORY_OPTION);
        return LIBRDP_STATUS_OK;
    }
    if (stage ==
        SMOKE_DRIVE_STAGE_OPEN_LIMIT_DIRECTORY_TERTIARY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->file.file_id == 0u)
            return smoke_drive_complete_limits_invalid(platform, completion);
        platform->drive_directory = completion->file;
        smoke_drive_submit_notify(
            platform,
            SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_FIRST_PENDING,
            platform->drive_file,
            RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_FILE_NAME);
        platform->drive_pending_request_ids[0] =
            platform->drive_next_request_id;
        return LIBRDP_STATUS_OK;
    }
    if (stage ==
        SMOKE_DRIVE_STAGE_REJECT_LIMIT_NOTIFY_THIRD)
    {
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_NOTIFY_DIRECTORY ||
            io_result != LIBRDP_SERVER_DRIVE_IO_RESOURCE_LIMIT)
            return smoke_drive_complete_limits_invalid(platform, completion);
        atomic_store_explicit(
            &platform->drive_stage,
            SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_WAIT_CANCEL_FIRST,
            memory_order_release);
        return LIBRDP_STATUS_OK;
    }
    if (stage ==
        SMOKE_DRIVE_STAGE_CLOSE_LIMIT_DIRECTORY_TERTIARY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CLOSE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
            return smoke_drive_complete_limits_invalid(platform, completion);
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_CLOSE_LIMIT_DIRECTORY_SECONDARY,
            LIBRDP_SERVER_DRIVE_CLOSE,
            platform->drive_secondary_file,
            NULL,
            NULL,
            0u,
            0u,
            0u,
            0u,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage ==
        SMOKE_DRIVE_STAGE_CLOSE_LIMIT_DIRECTORY_SECONDARY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CLOSE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
            return smoke_drive_complete_limits_invalid(platform, completion);
        smoke_drive_submit(
            platform,
            SMOKE_DRIVE_STAGE_CLOSE_LIMIT_DIRECTORY_PRIMARY,
            LIBRDP_SERVER_DRIVE_CLOSE,
            platform->drive_file,
            NULL,
            NULL,
            0u,
            0u,
            0u,
            0u,
            0u,
            0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage ==
        SMOKE_DRIVE_STAGE_CLOSE_LIMIT_DIRECTORY_PRIMARY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CLOSE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
            return smoke_drive_complete_limits_invalid(platform, completion);
        atomic_store_explicit(&platform->drive_stage,
                              SMOKE_DRIVE_STAGE_COMPLETE,
                              memory_order_release);
        return LIBRDP_STATUS_OK;
    }
    return smoke_drive_complete_limits_invalid(platform, completion);
}

static librdp_status smoke_drive_complete(
    void* context,
    const server_platform_drive_completion* completion)
{
    smoke_platform* platform = (smoke_platform*)context;
    smoke_drive_stage stage = SMOKE_DRIVE_STAGE_DISABLED;
    librdp_server_drive_io_result io_result =
        LIBRDP_SERVER_DRIVE_IO_ERROR;
    uint8_t rename_payload[64];
    uint8_t size_payload[8];
    uint8_t delete_payload[1] = {1u};
    size_t rename_len = 0u;

    if (!platform || !completion)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (!platform->drive_profile)
        return LIBRDP_STATUS_OK;
    stage = (smoke_drive_stage)atomic_load_explicit(
        &platform->drive_stage,
        memory_order_acquire);
    io_result =
        librdp_server_drive_classify_io_status(completion->io_status);
    atomic_fetch_add_explicit(&platform->drive_completions,
                              1u,
                              memory_order_relaxed);
    if (platform->drive_profile->mode == SMOKE_DRIVE_NOTIFY)
    {
        return smoke_drive_complete_notify(platform,
                                           stage,
                                           io_result,
                                           completion);
    }
    if (platform->drive_profile->mode ==
        SMOKE_DRIVE_CONFINEMENT)
    {
        return smoke_drive_complete_confinement(platform,
                                                stage,
                                                io_result,
                                                completion);
    }
    if (platform->drive_profile->mode ==
        SMOKE_DRIVE_DEVICE_NODE)
    {
        return smoke_drive_complete_device_node(platform,
                                                stage,
                                                io_result,
                                                completion);
    }
    if (platform->drive_profile->mode ==
        SMOKE_DRIVE_LIMITS)
    {
        return smoke_drive_complete_limits(platform,
                                           stage,
                                           io_result,
                                           completion);
    }
    if (completion->request_id != platform->drive_next_request_id ||
        completion->type != LIBRDP_SERVER_DRIVE_REQUEST_COMPLETED ||
        completion->status != LIBRDP_STATUS_OK)
    {
        smoke_drive_fail(platform,
                         completion->status,
                         completion->io_status);
        return LIBRDP_STATUS_OK;
    }
    if (platform->drive_profile->mode ==
        SMOKE_DRIVE_INFORMATION)
    {
        return smoke_drive_complete_information(platform,
                                                stage,
                                                io_result,
                                                completion);
    }
    if (platform->drive_profile->mode ==
        SMOKE_DRIVE_METADATA)
    {
        return smoke_drive_complete_metadata(platform,
                                             stage,
                                             io_result,
                                             completion);
    }
    if (platform->drive_profile->mode ==
        SMOKE_DRIVE_ENUMERATION)
    {
        return smoke_drive_complete_enumeration(platform,
                                                stage,
                                                io_result,
                                                completion);
    }
    if (platform->drive_profile->mode ==
        SMOKE_DRIVE_LOCKING)
    {
        return smoke_drive_complete_locking(platform,
                                            stage,
                                            io_result,
                                            completion);
    }
    if (stage == SMOKE_DRIVE_STAGE_OPEN_FILE)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->file.file_id == 0u)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        platform->drive_file = completion->file;
        if (platform->drive_profile->mode == SMOKE_DRIVE_WRITABLE)
        {
            smoke_drive_submit(platform,
                               SMOKE_DRIVE_STAGE_WRITE_FILE,
                               LIBRDP_SERVER_DRIVE_WRITE,
                               platform->drive_file,
                               NULL,
                               smoke_drive_write_data,
                               sizeof(smoke_drive_write_data) - 1u,
                               0u,
                               0u,
                               0u,
                               0u,
                               0u);
        }
        else
        {
            smoke_drive_submit(platform,
                               SMOKE_DRIVE_STAGE_READ_FILE,
                               LIBRDP_SERVER_DRIVE_READ,
                               platform->drive_file,
                               NULL,
                               NULL,
                               0u,
                               0u,
                               0u,
                               (uint32_t)(sizeof(smoke_drive_marker_data) - 1u),
                               0u,
                               0u);
        }
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_READ_FILE)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_READ ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->data_len != sizeof(smoke_drive_marker_data) - 1u ||
            !completion->data ||
            memcmp(completion->data,
                   smoke_drive_marker_data,
                   completion->data_len) != 0)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(platform,
                           SMOKE_DRIVE_STAGE_QUERY_FILE,
                           LIBRDP_SERVER_DRIVE_QUERY_INFORMATION,
                           platform->drive_file,
                           NULL,
                           NULL,
                           0u,
                           LIBRDP_SERVER_DRIVE_FILE_ALL_INFORMATION,
                           0u,
                           0u,
                           0u,
                           0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_QUERY_FILE)
    {
        librdp_server_drive_metadata metadata;
        librdp_status metadata_status = LIBRDP_STATUS_OK;

        memset(&metadata, 0, sizeof(metadata));
        metadata_status = librdp_server_drive_metadata_init(&metadata);
        if (metadata_status == LIBRDP_STATUS_OK)
        {
            metadata_status = librdp_server_drive_decode_file_metadata(
                completion->information_class,
                completion->data,
                completion->data_len,
                &metadata);
        }
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_QUERY_INFORMATION ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            metadata_status != LIBRDP_STATUS_OK ||
            metadata.directory ||
            metadata.file_size != sizeof(smoke_drive_marker_data) - 1u)
        {
            fprintf(stderr,
                    "drive metadata mismatch operation=%u io_result=%u class=%u decode=%s data_len=%zu directory=%u file_size=%llu expected=%zu\n",
                    (unsigned int)completion->operation,
                    (unsigned int)io_result,
                    completion->information_class,
                    librdp_status_name(metadata_status),
                    completion->data_len,
                    metadata.directory,
                    (unsigned long long)metadata.file_size,
                    sizeof(smoke_drive_marker_data) - 1u);
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(platform,
                           SMOKE_DRIVE_STAGE_OPEN_DIRECTORY,
                           LIBRDP_SERVER_DRIVE_CREATE,
                           (librdp_server_drive_file_handle){0},
                           "",
                           NULL,
                           0u,
                           0u,
                           0u,
                           0u,
                           SMOKE_DRIVE_OPEN_EXISTING,
                           SMOKE_DRIVE_DIRECTORY_OPTION);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_OPEN_DIRECTORY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CREATE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->file.file_id == 0u)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        platform->drive_directory = completion->file;
        smoke_drive_submit(platform,
                           SMOKE_DRIVE_STAGE_QUERY_DIRECTORY,
                           LIBRDP_SERVER_DRIVE_QUERY_DIRECTORY,
                           platform->drive_directory,
                           "marker.txt",
                           NULL,
                           0u,
                           LIBRDP_SERVER_DRIVE_FILE_DIRECTORY_INFORMATION,
                           0u,
                           0u,
                           0u,
                           0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_QUERY_DIRECTORY)
    {
        librdp_server_drive_metadata metadata;
        char name[64];
        size_t name_len = 0u;
        size_t next_offset = 0u;

        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_QUERY_DIRECTORY ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            librdp_server_drive_metadata_init(&metadata) !=
                LIBRDP_STATUS_OK ||
            librdp_server_drive_decode_directory_entry(
                completion->information_class,
                completion->data,
                completion->data_len,
                0u,
                &metadata,
                name,
                sizeof(name),
                &name_len,
                &next_offset) != LIBRDP_STATUS_OK ||
            strcmp(name, "marker.txt") != 0 ||
            name_len != sizeof("marker.txt") ||
            next_offset != 0u)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(platform,
                           SMOKE_DRIVE_STAGE_WRITE_DENIED,
                           LIBRDP_SERVER_DRIVE_WRITE,
                           platform->drive_file,
                           NULL,
                           smoke_drive_write_data,
                           sizeof(smoke_drive_write_data) - 1u,
                           0u,
                           0u,
                           0u,
                           0u,
                           0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_WRITE_DENIED)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_WRITE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_ACCESS_DENIED)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        rename_len = smoke_drive_make_rename_payload(
            "renamed.txt",
            rename_payload,
            sizeof(rename_payload));
        if (rename_len == 0u)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_STATE,
                             0u);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(platform,
                           SMOKE_DRIVE_STAGE_RENAME_DENIED,
                           LIBRDP_SERVER_DRIVE_SET_INFORMATION,
                           platform->drive_file,
                           NULL,
                           rename_payload,
                           rename_len,
                           SMOKE_DRIVE_FILE_RENAME_INFORMATION,
                           0u,
                           0u,
                           0u,
                           0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_RENAME_DENIED)
    {
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_SET_INFORMATION ||
            io_result != LIBRDP_SERVER_DRIVE_IO_ACCESS_DENIED)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(platform,
                           SMOKE_DRIVE_STAGE_DELETE_DENIED,
                           LIBRDP_SERVER_DRIVE_SET_INFORMATION,
                           platform->drive_file,
                           NULL,
                           delete_payload,
                           sizeof(delete_payload),
                           SMOKE_DRIVE_FILE_DISPOSITION_INFORMATION,
                           0u,
                           0u,
                           0u,
                           0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_DELETE_DENIED)
    {
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_SET_INFORMATION ||
            io_result != LIBRDP_SERVER_DRIVE_IO_ACCESS_DENIED)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(platform,
                           SMOKE_DRIVE_STAGE_CLOSE_FILE,
                           LIBRDP_SERVER_DRIVE_CLOSE,
                           platform->drive_file,
                           NULL,
                           NULL,
                           0u,
                           0u,
                           0u,
                           0u,
                           0u,
                           0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_WRITE_FILE)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_WRITE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->transferred !=
                sizeof(smoke_drive_write_data) - 1u)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(platform,
                           SMOKE_DRIVE_STAGE_APPEND_FILE,
                           LIBRDP_SERVER_DRIVE_WRITE,
                           platform->drive_file,
                           NULL,
                           smoke_drive_append_data,
                           sizeof(smoke_drive_append_data) - 1u,
                           0u,
                           UINT64_MAX,
                           0u,
                           0u,
                           0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_APPEND_FILE)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_WRITE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->transferred !=
                sizeof(smoke_drive_append_data) - 1u)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(platform,
                           SMOKE_DRIVE_STAGE_FLUSH_FILE,
                           LIBRDP_SERVER_DRIVE_FLUSH,
                           platform->drive_file,
                           NULL,
                           NULL,
                           0u,
                           0u,
                           0u,
                           0u,
                           0u,
                           0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_FLUSH_FILE)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_FLUSH ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_write_u64_le(size_payload, 3u);
        smoke_drive_submit(platform,
                           SMOKE_DRIVE_STAGE_TRUNCATE_FILE,
                           LIBRDP_SERVER_DRIVE_SET_INFORMATION,
                           platform->drive_file,
                           NULL,
                           size_payload,
                           sizeof(size_payload),
                           SMOKE_DRIVE_FILE_END_OF_FILE_INFORMATION,
                           0u,
                           0u,
                           0u,
                           0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_TRUNCATE_FILE)
    {
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_SET_INFORMATION ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(platform,
                           SMOKE_DRIVE_STAGE_READ_TRUNCATED,
                           LIBRDP_SERVER_DRIVE_READ,
                           platform->drive_file,
                           NULL,
                           NULL,
                           0u,
                           0u,
                           0u,
                           16u,
                           0u,
                           0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_READ_TRUNCATED)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_READ ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS ||
            completion->data_len != 3u || !completion->data ||
            memcmp(completion->data, "wri", 3u) != 0)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        rename_len = smoke_drive_make_rename_payload(
            "renamed.bin",
            rename_payload,
            sizeof(rename_payload));
        if (rename_len == 0u)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_STATE,
                             0u);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(platform,
                           SMOKE_DRIVE_STAGE_RENAME_FILE,
                           LIBRDP_SERVER_DRIVE_SET_INFORMATION,
                           platform->drive_file,
                           NULL,
                           rename_payload,
                           rename_len,
                           SMOKE_DRIVE_FILE_RENAME_INFORMATION,
                           0u,
                           0u,
                           0u,
                           0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_RENAME_FILE)
    {
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_SET_INFORMATION ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(platform,
                           SMOKE_DRIVE_STAGE_DELETE_FILE,
                           LIBRDP_SERVER_DRIVE_SET_INFORMATION,
                           platform->drive_file,
                           NULL,
                           delete_payload,
                           sizeof(delete_payload),
                           SMOKE_DRIVE_FILE_DISPOSITION_INFORMATION,
                           0u,
                           0u,
                           0u,
                           0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_DELETE_FILE)
    {
        if (completion->operation !=
                LIBRDP_SERVER_DRIVE_SET_INFORMATION ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(platform,
                           SMOKE_DRIVE_STAGE_CLEANUP_FILE,
                           LIBRDP_SERVER_DRIVE_CLEANUP,
                           platform->drive_file,
                           NULL,
                           NULL,
                           0u,
                           0u,
                           0u,
                           0u,
                           0u,
                           0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_CLEANUP_FILE)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CLEANUP ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        smoke_drive_submit(platform,
                           SMOKE_DRIVE_STAGE_CLOSE_FILE,
                           LIBRDP_SERVER_DRIVE_CLOSE,
                           platform->drive_file,
                           NULL,
                           NULL,
                           0u,
                           0u,
                           0u,
                           0u,
                           0u,
                           0u);
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_CLOSE_FILE)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CLOSE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        if (platform->drive_profile->mode == SMOKE_DRIVE_WRITABLE)
        {
            atomic_store_explicit(&platform->drive_stage,
                                  SMOKE_DRIVE_STAGE_COMPLETE,
                                  memory_order_release);
        }
        else
        {
            smoke_drive_submit(platform,
                               SMOKE_DRIVE_STAGE_CLOSE_DIRECTORY,
                               LIBRDP_SERVER_DRIVE_CLOSE,
                               platform->drive_directory,
                               NULL,
                               NULL,
                               0u,
                               0u,
                               0u,
                               0u,
                               0u,
                               0u);
        }
        return LIBRDP_STATUS_OK;
    }
    if (stage == SMOKE_DRIVE_STAGE_CLOSE_DIRECTORY)
    {
        if (completion->operation != LIBRDP_SERVER_DRIVE_CLOSE ||
            io_result != LIBRDP_SERVER_DRIVE_IO_SUCCESS)
        {
            smoke_drive_fail(platform,
                             LIBRDP_STATUS_PROTOCOL_ERROR,
                             completion->io_status);
            return LIBRDP_STATUS_OK;
        }
        atomic_store_explicit(&platform->drive_stage,
                              SMOKE_DRIVE_STAGE_COMPLETE,
                              memory_order_release);
        return LIBRDP_STATUS_OK;
    }
    smoke_drive_fail(platform,
                     LIBRDP_STATUS_PROTOCOL_ERROR,
                     completion->io_status);
    return LIBRDP_STATUS_OK;
}

static librdp_status smoke_permission_start(
    void* context,
    const server_platform_permission_sink* sink)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (!platform || !sink || !sink->changed)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    platform->permission_sink = *sink;
    return LIBRDP_STATUS_OK;
}

static void smoke_permission_stop(void* context)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (platform)
        memset(&platform->permission_sink, 0, sizeof(platform->permission_sink));
}

static librdp_status smoke_permission_query(
    void* context,
    server_platform_permission_kind kind,
    server_platform_permission_state* state)
{
    if (!context || !state ||
        kind < SERVER_PLATFORM_PERMISSION_CAPTURE ||
        kind > SERVER_PLATFORM_PERMISSION_DRIVE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *state = SERVER_PLATFORM_PERMISSION_GRANTED;
    return LIBRDP_STATUS_OK;
}

static librdp_status smoke_permission_change(
    void* context,
    server_platform_permission_kind kind)
{
    smoke_platform* platform = (smoke_platform*)context;

    if (!platform || kind < SERVER_PLATFORM_PERMISSION_CAPTURE ||
        kind > SERVER_PLATFORM_PERMISSION_DRIVE)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (platform->permission_sink.changed)
    {
        platform->permission_sink.changed(
            kind,
            SERVER_PLATFORM_PERMISSION_GRANTED,
            platform->permission_sink.user_data);
    }
    return LIBRDP_STATUS_OK;
}

static const server_platform_capture_vtable smoke_capture_vtable = {
    SERVER_PLATFORM_CAPTURE_VERSION,
    sizeof(server_platform_capture_vtable),
    smoke_capture_start,
    smoke_capture_stop,
    smoke_capture_request,
    NULL,
};

static const server_platform_input_vtable smoke_input_vtable = {
    SERVER_PLATFORM_INPUT_VERSION,
    sizeof(server_platform_input_vtable),
    smoke_input_inject,
    smoke_input_release,
};

static const server_platform_drive_vtable smoke_drive_vtable = {
    SERVER_PLATFORM_DRIVE_VERSION,
    sizeof(server_platform_drive_vtable),
    smoke_drive_start,
    smoke_drive_stop,
    smoke_drive_present,
    smoke_drive_remove,
    smoke_drive_remove_peer,
    smoke_drive_complete,
    NULL,
};

static const server_platform_permission_vtable smoke_permission_vtable = {
    SERVER_PLATFORM_PERMISSION_VERSION,
    sizeof(server_platform_permission_vtable),
    smoke_permission_start,
    smoke_permission_stop,
    smoke_permission_query,
    smoke_permission_change,
    smoke_permission_change,
    NULL,
};

static void smoke_platform_init(smoke_platform* platform,
                                server_host_config* config,
                                server_client_clipboard_provider*
                                    clipboard_provider,
                                const smoke_drive_profile* drive_profile)
{
    size_t pixel = 0u;

    memset(platform, 0, sizeof(*platform));
    for (pixel = 0u; pixel < SMOKE_PIXEL_BYTES; pixel += 4u)
    {
        platform->pixels[pixel] = (uint8_t)(pixel / 4u);
        platform->pixels[pixel + 1u] = 0x5au;
        platform->pixels[pixel + 2u] = 0xc3u;
        platform->pixels[pixel + 3u] = 0xffu;
        platform->alternate_pixels[pixel] =
            (uint8_t)(0xf0u ^ (uint8_t)(pixel / 4u));
        platform->alternate_pixels[pixel + 1u] = 0xa5u;
        platform->alternate_pixels[pixel + 2u] = 0x3cu;
        platform->alternate_pixels[pixel + 3u] = 0xffu;
    }
    atomic_init(&platform->capture_requests, 0u);
    atomic_init(&platform->capture_variant, 0u);
    atomic_init(&platform->key_events, 0u);
    atomic_init(&platform->unicode_events, 0u);
    atomic_init(&platform->mouse_events, 0u);
    atomic_init(&platform->extended_mouse_events, 0u);
    atomic_init(&platform->input_validation_errors, 0u);
    atomic_init(&platform->drive_presentations, 0u);
    atomic_init(&platform->drive_removals, 0u);
    atomic_init(&platform->drive_stage,
                drive_profile ? SMOKE_DRIVE_STAGE_WAIT_VOLUME
                              : SMOKE_DRIVE_STAGE_DISABLED);
    atomic_init(&platform->drive_completions, 0u);
    atomic_init(&platform->drive_wait_cycles, 0u);
    atomic_init(&platform->releases, 0u);
    atomic_init(&platform->refresh_requests, 0u);
    atomic_init(&platform->output_suppressions, 0u);
    atomic_init(&platform->output_resumptions, 0u);
    config->platform.capture.vtable = &smoke_capture_vtable;
    config->platform.capture.context = platform;
    config->platform.input.vtable = &smoke_input_vtable;
    config->platform.input.context = platform;
    config->platform.clipboard.vtable =
        server_client_clipboard_provider_vtable();
    config->platform.clipboard.context = clipboard_provider;
    config->platform.drive.vtable = &smoke_drive_vtable;
    config->platform.drive.context = platform;
    config->platform.permission.vtable = &smoke_permission_vtable;
    config->platform.permission.context = platform;
    config->drive.enabled = 1;
    config->drive.read_only = drive_profile ? 0 : 1;
    platform->drive_profile = drive_profile;
}

static void smoke_host_trace_callback(
    const server_host_trace_event* event,
    void* user_data)
{
    smoke_platform* platform = (smoke_platform*)user_data;

    if (!platform || !event)
        return;
    if (event->type == SERVER_HOST_TRACE_REFRESH_REQUEST)
    {
        atomic_fetch_add_explicit(&platform->refresh_requests,
                                  1u,
                                  memory_order_release);
    }
    else if (event->type ==
             SERVER_HOST_TRACE_OUTPUT_SUPPRESSION)
    {
        atomic_uint* counter =
            event->value ?
                &platform->output_suppressions :
                &platform->output_resumptions;

        atomic_fetch_add_explicit(counter,
                                  1u,
                                  memory_order_release);
    }
}

/*
 * Open RDPEAR only after an authenticated peer has begun normal extension
 * traffic. A transient STATE result means DRDYNVC capability negotiation has
 * not completed yet and is retried on the next validated extension event.
 */
static void smoke_auth_redirection_extension_callback(
    librdp_server_peer* peer,
    const librdp_server_extension_event* event,
    void* user_data)
{
    smoke_auth_redirection* auth = (smoke_auth_redirection*)user_data;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !event || !auth)
        return;
    if (event->family == LIBRDP_SERVER_EXTENSION_AUTH_REDIRECTION)
    {
        static const uint8_t version_payload[4] = {0u, 0u, 0u, 0u};
        rdp_auth_redirection_response response;
        rdp_auth_redirection_negotiate_version version;
        librdp_server_extension_state state;

        memset(&response, 0, sizeof(response));
        memset(&version, 0, sizeof(version));
        status = rdp_auth_redirection_parse_negotiate_version_response(
            event->payload,
            event->payload_len,
            &response,
            &version);
        if (status == LIBRDP_STATUS_OK &&
            (response.call_id !=
                 RDP_AUTH_REDIRECTION_CALL_KERB_NEGOTIATE_VERSION ||
             response.status != 0u ||
             version.version != RDP_AUTH_REDIRECTION_VERSION))
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        if (status == LIBRDP_STATUS_OK)
            atomic_fetch_add_explicit(&auth->response_received,
                                      1u,
                                      memory_order_release);
        if (status == LIBRDP_STATUS_OK)
            status = librdp_server_peer_send_auth_redirection_call(
                peer,
                event->dynamic_channel_id,
                RDP_AUTH_REDIRECTION_PACKAGE_NTLM,
                RDP_AUTH_REDIRECTION_CALL_NTLM_NEGOTIATE_VERSION,
                version_payload,
                sizeof(version_payload));
        if (status == LIBRDP_STATUS_OK)
            status = librdp_server_peer_record_extension_timeout(
                peer,
                LIBRDP_SERVER_EXTENSION_AUTH_REDIRECTION);
        if (status == LIBRDP_STATUS_OK)
            status = librdp_server_peer_cancel_extension(
                peer,
                LIBRDP_SERVER_EXTENSION_AUTH_REDIRECTION);
        if (status == LIBRDP_STATUS_OK)
            status = librdp_server_extension_state_init(&state);
        if (status == LIBRDP_STATUS_OK)
            status = librdp_server_peer_get_extension_state(
                peer,
                LIBRDP_SERVER_EXTENSION_AUTH_REDIRECTION,
                &state);
        if (status == LIBRDP_STATUS_OK &&
            (!state.cancelled || state.pending_requests != 0u ||
             state.timeout_count != 1u ||
             state.last_status != LIBRDP_STATUS_OK))
            status = LIBRDP_STATUS_PROTOCOL_ERROR;
        if (status == LIBRDP_STATUS_OK)
            atomic_store_explicit(&auth->cancellation_verified,
                                  1u,
                                  memory_order_release);
        else
            atomic_store_explicit(&auth->failure_status,
                                  (int)status,
                                  memory_order_release);
        return;
    }
    if (atomic_load_explicit(&auth->open_requested,
                             memory_order_acquire) != 0u)
        return;
    status = librdp_server_peer_enable_extension_provider(
        peer,
        LIBRDP_SERVER_EXTENSION_AUTH_REDIRECTION,
        1);
    if (status == LIBRDP_STATUS_OK)
        status = librdp_server_peer_open_dynamic_channel(
            peer,
            SMOKE_AUTH_REDIRECTION_CHANNEL_ID,
            0u,
            RDP_AUTH_REDIRECTION_CHANNEL_NAME);
    if (status == LIBRDP_STATUS_OK)
    {
        atomic_store_explicit(&auth->open_requested,
                              1u,
                              memory_order_release);
    }
    else if (status != LIBRDP_STATUS_STATE)
    {
        atomic_store_explicit(&auth->failure_status,
                              (int)status,
                              memory_order_release);
    }
}

/* Send a typed version-negotiation call as soon as the client accepts DVC. */
static void smoke_auth_redirection_channel_callback(
    librdp_server_peer* peer,
    const librdp_server_channel_event* event,
    void* user_data)
{
    static const uint8_t version_payload[4] = {0u, 0u, 0u, 0u};
    smoke_auth_redirection* auth = (smoke_auth_redirection*)user_data;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !event || !auth ||
        event->type != LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_OPEN ||
        event->dynamic_channel_id != SMOKE_AUTH_REDIRECTION_CHANNEL_ID ||
        event->name_len != sizeof(RDP_AUTH_REDIRECTION_CHANNEL_NAME) - 1u ||
        memcmp(event->name,
               RDP_AUTH_REDIRECTION_CHANNEL_NAME,
               event->name_len) != 0)
        return;
    atomic_store_explicit(&auth->channel_opened,
                          1u,
                          memory_order_release);
    status = librdp_server_peer_send_auth_redirection_call(
        peer,
        event->dynamic_channel_id,
        RDP_AUTH_REDIRECTION_PACKAGE_KERBEROS,
        RDP_AUTH_REDIRECTION_CALL_KERB_NEGOTIATE_VERSION,
        version_payload,
        sizeof(version_payload));
    if (status == LIBRDP_STATUS_OK)
    {
        atomic_store_explicit(&auth->call_sent,
                              1u,
                              memory_order_release);
    }
    else
    {
        atomic_store_explicit(&auth->failure_status,
                              (int)status,
                              memory_order_release);
    }
}

/*
 * Own all host operations on one thread. Cross-thread cancellation is the
 * only host method invoked by the client side of the fixture.
 */
static void* smoke_host_main(void* user_data)
{
    smoke_host* fixture = (smoke_host*)user_data;

    if (!fixture)
        return NULL;
    fixture->status = server_host_start(fixture->host);
    if (fixture->status != LIBRDP_STATUS_OK)
        return NULL;
    atomic_store_explicit(&fixture->port,
                          server_host_local_port(fixture->host),
                          memory_order_release);
    for (;;)
    {
        librdp_status status = server_host_run_once(fixture->host, 20);

        if (status == LIBRDP_STATUS_OK || status == LIBRDP_STATUS_TIMEOUT)
            continue;
        if (status == LIBRDP_STATUS_CANCELLED)
        {
            fixture->status = LIBRDP_STATUS_OK;
            break;
        }
        fixture->status = status;
        break;
    }
    if (server_host_get_state(fixture->host) != SERVER_HOST_STOPPED)
        (void)server_host_stop(fixture->host);
    return NULL;
}

/*
 * Read one bounded X.224 request from a raw loopback peer. Polling keeps the
 * fixture cancellable when a client fails before reaching negotiation.
 */
static int smoke_security_peer_read_exact(smoke_security_peer* fixture,
                                          int fd,
                                          uint8_t* data,
                                          size_t length)
{
    uint64_t deadline_ns = smoke_now_ns() + 5000000000ULL;
    size_t offset = 0u;

    while (offset < length &&
           atomic_load_explicit(&fixture->stop, memory_order_acquire) == 0u)
    {
        struct pollfd pfd;
        ssize_t count = 0;
        int ready = 0;

        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLIN;
        do
        {
            ready = poll(&pfd, 1u, 50);
        } while (ready < 0 && errno == EINTR);
        if (ready < 0 || smoke_now_ns() >= deadline_ns)
            return 0;
        if (ready == 0)
            continue;
        count = recv(fd, data + offset, length - offset, 0);
        if (count <= 0)
            return 0;
        offset += (size_t)count;
    }
    return offset == length;
}

static int smoke_security_peer_read_x224(smoke_security_peer* fixture,
                                         int fd)
{
    uint8_t header[4];
    uint8_t body[4092];
    size_t packet_length = 0u;

    if (!smoke_security_peer_read_exact(fixture,
                                        fd,
                                        header,
                                        sizeof(header)) ||
        header[0] != 3u)
        return 0;
    packet_length = ((size_t)header[2] << 8u) | (size_t)header[3];
    if (packet_length < sizeof(header) ||
        packet_length > sizeof(header) + sizeof(body))
        return 0;
    return smoke_security_peer_read_exact(fixture,
                                          fd,
                                          body,
                                          packet_length - sizeof(header));
}

/*
 * Present a deterministic X.224 security boundary without running later RDP
 * phases. Certificate modes perform a real server-side TLS handshake, while
 * the invalid mode deliberately returns non-TLS bytes after selecting TLS.
 */
static void* smoke_security_peer_main(void* user_data)
{
    static const uint8_t invalid_tls[] = {
        'N', 'O', 'T', '-', 'T', 'L', 'S', '\r', '\n'
    };
    smoke_security_peer* fixture = (smoke_security_peer*)user_data;
    struct sockaddr_in address;
    struct timeval timeout = {5, 0};
    socklen_t address_len = (socklen_t)sizeof(address);
    SSL_CTX* tls_context = NULL;
    SSL* tls = NULL;
    sigset_t blocked_signals;
    int listener = -1;
    int client = -1;
    int ok = 0;

    if (!fixture)
        return NULL;
    fixture->status = LIBRDP_STATUS_IO_ERROR;
    if (sigemptyset(&blocked_signals) != 0 ||
        sigaddset(&blocked_signals, SIGPIPE) != 0 ||
        pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL) != 0)
        return NULL;
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0)
        goto cleanup;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(listener,
             (const struct sockaddr*)&address,
             (socklen_t)sizeof(address)) != 0 ||
        getsockname(listener,
                    (struct sockaddr*)&address,
                    &address_len) != 0 ||
        listen(listener, 1) != 0)
        goto cleanup;
    atomic_store_explicit(&fixture->port,
                          (unsigned int)ntohs(address.sin_port),
                          memory_order_release);
    while (atomic_load_explicit(&fixture->stop,
                                memory_order_acquire) == 0u)
    {
        struct pollfd pfd;
        int ready = 0;

        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = listener;
        pfd.events = POLLIN;
        do
        {
            ready = poll(&pfd, 1u, 50);
        } while (ready < 0 && errno == EINTR);
        if (ready < 0)
            goto cleanup;
        if (ready == 0)
            continue;
        client = accept(listener, NULL, NULL);
        if (client < 0 && errno == EINTR)
            continue;
        if (client < 0)
            goto cleanup;
        break;
    }
    if (client < 0 ||
        setsockopt(client,
                   SOL_SOCKET,
                   SO_RCVTIMEO,
                   &timeout,
                   (socklen_t)sizeof(timeout)) != 0 ||
        setsockopt(client,
                   SOL_SOCKET,
                   SO_SNDTIMEO,
                   &timeout,
                   (socklen_t)sizeof(timeout)) != 0 ||
        !smoke_security_peer_read_x224(fixture, client))
        goto cleanup;
    {
        uint8_t response[] = {
            0x03u, 0x00u, 0x00u, 0x13u,
            0x0eu, 0xd0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x02u, 0x00u, 0x08u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u
        };

        if (fixture->mode != SMOKE_SECURITY_PEER_DOWNGRADE)
            response[15] = 0x01u;
        if (!test_server_send_all(client, response, sizeof(response)))
            goto cleanup;
    }
    if (fixture->mode == SMOKE_SECURITY_PEER_TLS_INVALID)
    {
        if (!test_server_send_all(client,
                                  invalid_tls,
                                  sizeof(invalid_tls)))
            goto cleanup;
    }
    else if (fixture->mode == SMOKE_SECURITY_PEER_TLS_CERTIFICATE)
    {
        int tls_result = 0;

        if (!fixture->certificate_path || !fixture->private_key_path)
            goto cleanup;
        tls_context = SSL_CTX_new(TLS_server_method());
        if (!tls_context ||
            SSL_CTX_use_certificate_chain_file(
                tls_context,
                fixture->certificate_path) != 1 ||
            SSL_CTX_use_PrivateKey_file(tls_context,
                                        fixture->private_key_path,
                                        SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(tls_context) != 1)
            goto cleanup;
        tls = SSL_new(tls_context);
        if (!tls || SSL_set_fd(tls, client) != 1)
            goto cleanup;
        tls_result = SSL_accept(tls);
        if (tls_result != 1)
            ERR_clear_error();
    }
    ok = 1;

cleanup:
    SSL_free(tls);
    SSL_CTX_free(tls_context);
    if (client >= 0)
        close(client);
    if (listener >= 0)
        close(listener);
    fixture->status = ok ? LIBRDP_STATUS_OK : LIBRDP_STATUS_IO_ERROR;
    return NULL;
}

/*
 * Complete X.224 and TLS through the public server API, then stop dispatching
 * as soon as CredSSP authentication begins. The client can therefore exercise
 * its own bounded CredSSP read without a synthetic TLS implementation.
 */
static void* smoke_nla_stall_main(void* user_data)
{
    smoke_nla_stall* fixture = (smoke_nla_stall*)user_data;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;

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
    while (atomic_load_explicit(&fixture->stop, memory_order_acquire) == 0u &&
           !peer)
    {
        fixture->status = librdp_server_accept(server, 20, &peer);
        if (fixture->status == LIBRDP_STATUS_TIMEOUT)
            continue;
        if (fixture->status != LIBRDP_STATUS_OK)
            goto cleanup;
    }
    while (atomic_load_explicit(&fixture->stop, memory_order_acquire) == 0u &&
           peer)
    {
        if (librdp_server_peer_get_state(peer) ==
            LIBRDP_SERVER_PEER_NLA_AUTHENTICATING)
        {
            atomic_store_explicit(&fixture->authenticating,
                                  1u,
                                  memory_order_release);
            break;
        }
        fixture->status = librdp_server_peer_run_once(peer, 20);
        if (fixture->status == LIBRDP_STATUS_TIMEOUT)
            continue;
        if (fixture->status != LIBRDP_STATUS_OK)
            goto cleanup;
    }
    while (atomic_load_explicit(&fixture->stop, memory_order_acquire) == 0u)
    {
        struct timespec delay = {0, 10000000L};

        (void)nanosleep(&delay, NULL);
    }
    fixture->status = LIBRDP_STATUS_OK;

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

static librdp_status smoke_send_all(int fd,
                                    const uint8_t* data,
                                    size_t length)
{
    size_t offset = 0u;
#ifdef MSG_NOSIGNAL
    const int send_flags = MSG_NOSIGNAL;
#else
    const int send_flags = 0;
#endif

    if (fd < 0 || (!data && length > 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    while (offset < length)
    {
        ssize_t written = send(fd,
                               data + offset,
                               length - offset,
                               send_flags);

        if (written > 0)
        {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        if (written < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            struct pollfd descriptor = {fd, POLLOUT, 0};
            int ready = poll(&descriptor, 1, 1000);

            if (ready > 0 &&
                (descriptor.revents & POLLOUT) != 0)
                continue;
            return ready == 0 ? LIBRDP_STATUS_TIMEOUT
                              : LIBRDP_STATUS_IO_ERROR;
        }
        return (written < 0 &&
                (errno == EPIPE || errno == ECONNRESET))
                   ? LIBRDP_STATUS_CLOSED
                   : LIBRDP_STATUS_IO_ERROR;
    }
    return LIBRDP_STATUS_OK;
}

static librdp_status smoke_integrity_send_slowpath(
    librdp_server_peer* peer,
    smoke_integrity_tamper tamper)
{
    rdp_buffer slowpath;
    rdp_buffer secured;
    rdp_buffer mcs;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !peer->standard_security_ready)
        return LIBRDP_STATUS_STATE;
    rdp_buffer_init(&slowpath);
    rdp_buffer_init(&secured);
    rdp_buffer_init(&mcs);
    status = rdp_slowpath_write_server_synchronize(
        &slowpath,
        peer->share_id,
        (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
        peer->user_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_write_encrypted_pdu(
            &secured,
            &peer->standard_security,
            0u,
            slowpath.data,
            slowpath.length);
    if (status == LIBRDP_STATUS_OK && secured.length <= 12u)
        status = LIBRDP_STATUS_PROTOCOL_ERROR;
    if (status == LIBRDP_STATUS_OK)
    {
        if (tamper == SMOKE_INTEGRITY_SLOWPATH_MAC)
            secured.data[4] ^= 0x80u;
        else if (tamper == SMOKE_INTEGRITY_SLOWPATH_CIPHERTEXT)
            secured.data[secured.length - 1u] ^= 0x01u;
        else
            status = LIBRDP_STATUS_INVALID_ARGUMENT;
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_mcs_write_send_data_indication(
            &mcs,
            peer->user_id,
            (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
            secured.data,
            secured.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_server_send_mcs_pdu(peer, &mcs);
    rdp_buffer_free(&mcs);
    rdp_buffer_free(&secured);
    rdp_buffer_free(&slowpath);
    return status;
}

/*
 * Wrap one server-to-client fast-path update with the active Standard
 * Security context. Integrity fixtures may corrupt the completed signature;
 * functional fixtures send the exact authenticated packet.
 */
static librdp_status smoke_standard_send_fastpath(
    librdp_server_peer* peer,
    const uint8_t* updates,
    size_t updates_len,
    int corrupt_signature)
{
    rdp_buffer encrypted;
    rdp_buffer wire;
    uint8_t signature[8] = {0};
    size_t signature_offset = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !peer->standard_security_ready)
        return LIBRDP_STATUS_STATE;
    if (!updates && updates_len > 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&encrypted);
    rdp_buffer_init(&wire);
    status = rdp_security_mac_signature(
        &peer->standard_security,
        updates,
        updates_len,
        signature);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&encrypted,
                                   updates,
                                   updates_len);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_security_encrypt_payload(
            &peer->standard_security,
            encrypted.data,
            encrypted.length);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_fastpath_write_header(
            &wire,
            RDP_FASTPATH_OUTPUT_ACTION_FASTPATH,
            RDP_FASTPATH_OUTPUT_ENCRYPTED,
            sizeof(signature) + encrypted.length);
    signature_offset = wire.length;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&wire,
                                   signature,
                                   sizeof(signature));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append(&wire,
                                   encrypted.data,
                                   encrypted.length);
    if (status == LIBRDP_STATUS_OK)
    {
        if (corrupt_signature)
            wire.data[signature_offset] ^= 0x40u;
        status = smoke_send_all(peer->fd,
                                wire.data,
                                wire.length);
    }
    OPENSSL_cleanse(signature, sizeof(signature));
    rdp_buffer_free(&wire);
    rdp_buffer_free(&encrypted);
    return status;
}

static librdp_status smoke_integrity_send_fastpath(
    librdp_server_peer* peer)
{
    rdp_buffer update;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&update);
    status = rdp_fastpath_write_update(
        &update,
        RDP_FASTPATH_UPDATE_SYNCHRONIZE,
        RDP_FASTPATH_FRAGMENT_SINGLE,
        0u,
        0u,
        NULL,
        0u);
    if (status == LIBRDP_STATUS_OK)
        status = smoke_standard_send_fastpath(peer,
                                              update.data,
                                              update.length,
                                              1);
    rdp_buffer_free(&update);
    return status;
}

/*
 * Send one authenticated fast-path bitmap update containing both raw
 * bottom-up pixels and RLE pixels. The rectangles are disjoint so the final
 * whole-surface digest proves that each decoder reached the normalized
 * framebuffer.
 */
static librdp_status smoke_fastpath_bitmap_send(
    librdp_server_peer* peer)
{
    static const uint8_t raw_pixels[] = {
        0x90u, 0x80u, 0x70u, 0xffu,
        0x60u, 0x50u, 0x40u, 0xffu,
        0x30u, 0x20u, 0x10u, 0xffu,
        0xc0u, 0xb0u, 0xa0u, 0xffu,
    };
    static const uint8_t rle_pixels[] = {
        0xfdu, 0xfeu, 0xfeu, 0xfdu,
    };
    rdp_bitmap_rect rects[2];
    rdp_buffer bitmap;
    rdp_buffer update;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(rects, 0, sizeof(rects));
    rects[0].dest_left = 3u;
    rects[0].dest_top = 5u;
    rects[0].dest_right = 4u;
    rects[0].dest_bottom = 6u;
    rects[0].width = 2u;
    rects[0].height = 2u;
    rects[0].bits_per_pixel = 32u;
    rects[0].data = raw_pixels;
    rects[0].data_len = (uint32_t)sizeof(raw_pixels);
    rects[1].dest_left = 9u;
    rects[1].dest_top = 7u;
    rects[1].dest_right = 10u;
    rects[1].dest_bottom = 8u;
    rects[1].width = 2u;
    rects[1].height = 2u;
    rects[1].bits_per_pixel = 32u;
    rects[1].flags = RDP_BITMAP_FLAG_COMPRESSED |
                     RDP_BITMAP_FLAG_NO_COMPRESSION_HEADER;
    rects[1].data = rle_pixels;
    rects[1].data_len = (uint32_t)sizeof(rle_pixels);

    rdp_buffer_init(&bitmap);
    rdp_buffer_init(&update);
    status = rdp_bitmap_write_fastpath_update(
        &bitmap,
        rects,
        (uint16_t)(sizeof(rects) / sizeof(rects[0])));
    if (status == LIBRDP_STATUS_OK)
        status = rdp_fastpath_write_update(
            &update,
            RDP_FASTPATH_UPDATE_BITMAP,
            RDP_FASTPATH_FRAGMENT_SINGLE,
            0u,
            0u,
            bitmap.data,
            bitmap.length);
    if (status == LIBRDP_STATUS_OK)
        status = smoke_standard_send_fastpath(peer,
                                              update.data,
                                              update.length,
                                              0);
    rdp_buffer_free(&update);
    rdp_buffer_free(&bitmap);
    return status;
}

/*
 * Send a 3x3 NSCodec tile against the lower-right desktop edge. The codec
 * planes mix literal and RLE data so the client traverses both plane paths.
 */
static librdp_status smoke_fastpath_nscodec_send(
    librdp_server_peer* peer)
{
    static const uint8_t nscodec_stream[] = {
        0x09u, 0x00u, 0x00u, 0x00u,
        0x07u, 0x00u, 0x00u, 0x00u,
        0x07u, 0x00u, 0x00u, 0x00u,
        0x07u, 0x00u, 0x00u, 0x00u,
        0x01u, 0x00u, 0x00u, 0x00u,
        0x0au, 0x14u, 0x1eu,
        0x28u, 0x32u, 0x3cu,
        0x46u, 0x50u, 0x5au,
        0x00u, 0x00u, 0x03u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x03u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0xffu, 0xffu, 0x03u,
        0xffu, 0xffu, 0xffu, 0xffu
    };
    rdp_surface_bits bits;
    rdp_buffer commands;
    rdp_buffer update;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&bits, 0, sizeof(bits));
    bits.command_type = RDP_SURFACE_COMMAND_SET_BITS;
    bits.dest_left = (uint16_t)(SMOKE_WIDTH - 3u);
    bits.dest_top = (uint16_t)(SMOKE_HEIGHT - 3u);
    bits.dest_right = (uint16_t)SMOKE_WIDTH;
    bits.dest_bottom = (uint16_t)SMOKE_HEIGHT;
    bits.bpp = 32u;
    bits.codec_id = RDP_SURFACE_CODEC_NSCODEC;
    bits.width = 3u;
    bits.height = 3u;
    bits.bitmap_data_length = (uint32_t)sizeof(nscodec_stream);
    bits.bitmap_data = nscodec_stream;
    rdp_buffer_init(&commands);
    rdp_buffer_init(&update);
    status = rdp_surface_commands_write_bits(&commands, &bits);
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_fastpath_write_update(
            &update,
            RDP_FASTPATH_UPDATE_SURFACE_COMMANDS,
            RDP_FASTPATH_FRAGMENT_SINGLE,
            0u,
            0u,
            commands.data,
            commands.length);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = smoke_standard_send_fastpath(peer,
                                              update.data,
                                              update.length,
                                              0);
    }
    rdp_buffer_free(&update);
    rdp_buffer_free(&commands);
    return status;
}

enum smoke_rfx_block_type
{
    SMOKE_RFX_BLOCK_SYNC = 0xccc0u,
    SMOKE_RFX_BLOCK_CODEC_VERSIONS = 0xccc1u,
    SMOKE_RFX_BLOCK_CHANNELS = 0xccc2u,
    SMOKE_RFX_BLOCK_CONTEXT = 0xccc3u,
    SMOKE_RFX_BLOCK_FRAME_BEGIN = 0xccc4u,
    SMOKE_RFX_BLOCK_FRAME_END = 0xccc5u,
    SMOKE_RFX_BLOCK_REGION = 0xccc6u,
    SMOKE_RFX_BLOCK_EXTENSION = 0xccc7u,
    SMOKE_RFX_BLOCK_REGION_DATA = 0xcac1u,
    SMOKE_RFX_BLOCK_TILESET = 0xcac2u,
    SMOKE_RFX_BLOCK_TILE = 0xcac3u
};

static librdp_status smoke_rfx_append_block(
    rdp_buffer* output,
    uint16_t type,
    const rdp_buffer* payload)
{
    librdp_status status = LIBRDP_STATUS_OK;

    if (!output || !payload ||
        payload->length > UINT32_MAX - 6u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    status = rdp_buffer_append_u16_le(output, type);
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_buffer_append_u32_le(
            output,
            (uint32_t)payload->length + 6u);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_buffer_append(output,
                                   payload->data,
                                   payload->length);
    }
    return status;
}

static librdp_status smoke_rfx_append_channel_block(
    rdp_buffer* output,
    uint16_t type,
    uint8_t channel_id,
    const rdp_buffer* payload)
{
    rdp_buffer wrapped;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!output || !payload)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&wrapped);
    status = rdp_buffer_append_u8(&wrapped, 1u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&wrapped, channel_id);
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_buffer_append(&wrapped,
                                   payload->data,
                                   payload->length);
    }
    if (status == LIBRDP_STATUS_OK)
        status = smoke_rfx_append_block(output, type, &wrapped);
    rdp_buffer_free(&wrapped);
    return status;
}

/*
 * Append one zero-coefficient RemoteFX tile and its matching region. Keeping
 * the vector construction typed makes the smoke sensitive to block framing,
 * region placement, entropy decoding, and tile clipping.
 */
static librdp_status smoke_rfx_append_region(
    rdp_buffer* output,
    uint16_t x,
    uint16_t y,
    uint16_t tile_x)
{
    rdp_buffer payload;
    rdp_buffer tile;
    rdp_buffer zeroes;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!output)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);
    rdp_buffer_init(&tile);
    rdp_buffer_init(&zeroes);

    status = rdp_buffer_append_u8(&payload, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 1u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, x);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, y);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 64u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 64u);
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_buffer_append_u16_le(
            &payload,
            SMOKE_RFX_BLOCK_REGION_DATA);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 1u);
    if (status == LIBRDP_STATUS_OK)
    {
        status = smoke_rfx_append_channel_block(
            output,
            SMOKE_RFX_BLOCK_REGION,
            0u,
            &payload);
    }

    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_rfx_rlgr_write_zeroes(
            &zeroes,
            RDP_RFX_TILE_COEFFICIENTS);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_buffer_append_u16_le(
            &tile,
            SMOKE_RFX_BLOCK_TILE);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_buffer_append_u32_le(
            &tile,
            19u + (uint32_t)zeroes.length * 3u);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&tile, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&tile, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&tile, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&tile, tile_x);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&tile, 0u);
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_buffer_append_u16_le(
            &tile,
            (uint16_t)zeroes.length);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_buffer_append_u16_le(
            &tile,
            (uint16_t)zeroes.length);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_buffer_append_u16_le(
            &tile,
            (uint16_t)zeroes.length);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_buffer_append(&tile,
                                   zeroes.data,
                                   zeroes.length);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_buffer_append(&tile,
                                   zeroes.data,
                                   zeroes.length);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_buffer_append(&tile,
                                   zeroes.data,
                                   zeroes.length);
    }

    payload.length = 0u;
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_buffer_append_u16_le(
            &payload,
            SMOKE_RFX_BLOCK_TILESET);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&payload, 1u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&payload, 64u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 1u);
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_buffer_append_u32_le(
            &payload,
            (uint32_t)tile.length);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        static const uint8_t quant[] = {
            0x11u, 0x11u, 0x11u, 0x11u, 0x11u
        };

        status = rdp_buffer_append(&payload,
                                   quant,
                                   sizeof(quant));
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_buffer_append(&payload,
                                   tile.data,
                                   tile.length);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = smoke_rfx_append_channel_block(
            output,
            SMOKE_RFX_BLOCK_EXTENSION,
            0u,
            &payload);
    }

    rdp_buffer_free(&zeroes);
    rdp_buffer_free(&tile);
    rdp_buffer_free(&payload);
    return status;
}

static librdp_status smoke_rfx_build_stream(
    rdp_buffer* output,
    uint16_t width,
    uint16_t frame_id,
    uint16_t region_count)
{
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t region = 0u;

    if (!output ||
        (region_count != 1u && region_count != 2u) ||
        width != (uint16_t)(region_count * 64u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&payload);

    status = rdp_buffer_append_u32_le(&payload, 0xcaccaccau);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 0x0100u);
    if (status == LIBRDP_STATUS_OK)
    {
        status = smoke_rfx_append_block(
            output,
            SMOKE_RFX_BLOCK_SYNC,
            &payload);
    }
    payload.length = 0u;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&payload, 1u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&payload, 1u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 0x0100u);
    if (status == LIBRDP_STATUS_OK)
    {
        status = smoke_rfx_append_block(
            output,
            SMOKE_RFX_BLOCK_CODEC_VERSIONS,
            &payload);
    }
    payload.length = 0u;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&payload, 1u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&payload, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, width);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 64u);
    if (status == LIBRDP_STATUS_OK)
    {
        status = smoke_rfx_append_block(
            output,
            SMOKE_RFX_BLOCK_CHANNELS,
            &payload);
    }
    payload.length = 0u;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u8(&payload, 0u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 64u);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, 0x0200u);
    if (status == LIBRDP_STATUS_OK)
    {
        status = smoke_rfx_append_channel_block(
            output,
            SMOKE_RFX_BLOCK_CONTEXT,
            0xffu,
            &payload);
    }
    payload.length = 0u;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u32_le(&payload, frame_id);
    if (status == LIBRDP_STATUS_OK)
        status = rdp_buffer_append_u16_le(&payload, region_count);
    if (status == LIBRDP_STATUS_OK)
    {
        status = smoke_rfx_append_channel_block(
            output,
            SMOKE_RFX_BLOCK_FRAME_BEGIN,
            0u,
            &payload);
    }
    for (region = 0u;
         status == LIBRDP_STATUS_OK && region < region_count;
         region++)
    {
        status = smoke_rfx_append_region(
            output,
            (uint16_t)(region * 64u),
            0u,
            region);
    }
    payload.length = 0u;
    if (status == LIBRDP_STATUS_OK)
    {
        status = smoke_rfx_append_channel_block(
            output,
            SMOKE_RFX_BLOCK_FRAME_END,
            0u,
            &payload);
    }
    rdp_buffer_free(&payload);
    return status;
}

/*
 * Send independent single- and multi-tile RemoteFX streams in one encrypted
 * fast-path update. The second stream uses the image codec identifier and
 * therefore also validates that both negotiated Surface Bits variants route
 * through the same normalized decoder.
 */
static librdp_status smoke_fastpath_rfx_send(
    librdp_server_peer* peer)
{
    rdp_surface_bits bits;
    rdp_buffer single;
    rdp_buffer multi;
    rdp_buffer commands;
    rdp_buffer update;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&single);
    rdp_buffer_init(&multi);
    rdp_buffer_init(&commands);
    rdp_buffer_init(&update);
    status = smoke_rfx_build_stream(&single, 64u, 7u, 1u);
    if (status == LIBRDP_STATUS_OK)
        status = smoke_rfx_build_stream(&multi, 128u, 8u, 2u);

    memset(&bits, 0, sizeof(bits));
    bits.command_type = RDP_SURFACE_COMMAND_SET_BITS;
    bits.dest_left = 0u;
    bits.dest_top = 0u;
    bits.dest_right = 64u;
    bits.dest_bottom = 64u;
    bits.bpp = 32u;
    bits.codec_id = RDP_SURFACE_CODEC_REMOTEFX;
    bits.width = 64u;
    bits.height = 64u;
    bits.bitmap_data_length = (uint32_t)single.length;
    bits.bitmap_data = single.data;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_surface_commands_write_bits(&commands, &bits);

    bits.dest_left = 64u;
    bits.dest_top = 64u;
    bits.dest_right = 192u;
    bits.dest_bottom = 128u;
    bits.codec_id = RDP_SURFACE_CODEC_IMAGE_REMOTEFX;
    bits.width = 128u;
    bits.height = 64u;
    bits.bitmap_data_length = (uint32_t)multi.length;
    bits.bitmap_data = multi.data;
    if (status == LIBRDP_STATUS_OK)
        status = rdp_surface_commands_write_bits(&commands, &bits);
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_fastpath_write_update(
            &update,
            RDP_FASTPATH_UPDATE_SURFACE_COMMANDS,
            RDP_FASTPATH_FRAGMENT_SINGLE,
            0u,
            0u,
            commands.data,
            commands.length);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = smoke_standard_send_fastpath(
            peer,
            update.data,
            update.length,
            0);
    }
    rdp_buffer_free(&update);
    rdp_buffer_free(&commands);
    rdp_buffer_free(&multi);
    rdp_buffer_free(&single);
    return status;
}

static int smoke_integrity_wait_for_client_close(int fd)
{
    unsigned int attempt = 0u;

    for (attempt = 0u; attempt < 100u; attempt++)
    {
        struct pollfd descriptor = {
            fd,
            (short)(POLLIN | POLLHUP),
            0
        };
        uint8_t discard[256];
        int ready = poll(&descriptor, 1, 50);

        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0)
            continue;
        if ((descriptor.revents &
             (POLLERR | POLLNVAL)) != 0)
            return 1;
        if ((descriptor.revents &
             (POLLIN | POLLHUP)) != 0)
        {
            ssize_t received = recv(fd,
                                    discard,
                                    sizeof(discard),
                                    0);

            if (received == 0)
                return 1;
            if (received < 0 &&
                (errno == ECONNRESET || errno == ENOTCONN))
                return 1;
            if (received < 0 &&
                errno != EINTR &&
                errno != EAGAIN &&
                errno != EWOULDBLOCK)
                return 0;
        }
    }
    return 0;
}

/*
 * Accept one loopback peer and drive the public server lifecycle until
 * activation. Callers retain ownership of the server and returned peer.
 */
static librdp_status smoke_server_accept_active(
    librdp_server* server,
    librdp_server_peer** peer)
{
    unsigned int attempt = 0u;
    librdp_status status = LIBRDP_STATUS_TIMEOUT;

    if (!server || !peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *peer = NULL;
    for (attempt = 0u; attempt < 500u && !*peer; attempt++)
    {
        status = librdp_server_accept(server, 20, peer);
        if (status == LIBRDP_STATUS_TIMEOUT)
            continue;
        if (status != LIBRDP_STATUS_OK)
            return status;
    }
    if (!*peer)
        return LIBRDP_STATUS_TIMEOUT;
    for (attempt = 0u; attempt < 500u; attempt++)
    {
        if (librdp_server_peer_get_state(*peer) ==
            LIBRDP_SERVER_PEER_ACTIVE)
            return LIBRDP_STATUS_OK;
        status = librdp_server_peer_run_once(*peer, 20);
        if (status != LIBRDP_STATUS_OK &&
            status != LIBRDP_STATUS_TIMEOUT)
            return status;
    }
    return librdp_server_peer_get_state(*peer) ==
                   LIBRDP_SERVER_PEER_ACTIVE
               ? LIBRDP_STATUS_OK
               : LIBRDP_STATUS_TIMEOUT;
}

/*
 * Complete a real Standard Security activation, inject exactly one corrupted
 * encrypted packet, and retain the peer until the client closes its socket.
 * Each fixture instance owns one connection so cipher counters cannot leak
 * between tamper variants.
 */
static void* smoke_integrity_peer_main(void* user_data)
{
    smoke_integrity_peer* fixture =
        (smoke_integrity_peer*)user_data;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;

    if (!fixture)
        return NULL;
    fixture->status = LIBRDP_STATUS_TIMEOUT;
    server = librdp_server_new(&fixture->config);
    if (!server)
    {
        fixture->status = LIBRDP_STATUS_NO_MEMORY;
        return NULL;
    }
    fixture->status = librdp_server_listen(server);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    atomic_store_explicit(&fixture->port,
                          librdp_server_local_port(server),
                          memory_order_release);
    fixture->status = smoke_server_accept_active(server, &peer);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    if (fixture->tamper == SMOKE_INTEGRITY_FASTPATH_MAC)
        fixture->status = smoke_integrity_send_fastpath(peer);
    else
        fixture->status = smoke_integrity_send_slowpath(
            peer,
            fixture->tamper);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    atomic_store_explicit(&fixture->packet_sent,
                          1u,
                          memory_order_release);
    if (!smoke_integrity_wait_for_client_close(peer->fd))
    {
        fixture->status = LIBRDP_STATUS_TIMEOUT;
        goto cleanup;
    }
    atomic_store_explicit(&fixture->client_closed,
                          1u,
                          memory_order_release);
    fixture->status = LIBRDP_STATUS_OK;

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

/*
 * Host one deterministic fast-path graphics fixture until the client has
 * verified the framebuffer and closed the transport.
 */
static void* smoke_fastpath_peer_main(void* user_data)
{
    smoke_fastpath_peer* fixture =
        (smoke_fastpath_peer*)user_data;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;

    if (!fixture || !fixture->send)
        return NULL;
    fixture->status = LIBRDP_STATUS_TIMEOUT;
    server = librdp_server_new(&fixture->config);
    if (!server)
    {
        fixture->status = LIBRDP_STATUS_NO_MEMORY;
        return NULL;
    }
    fixture->status = librdp_server_listen(server);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    atomic_store_explicit(&fixture->port,
                          librdp_server_local_port(server),
                          memory_order_release);
    fixture->status = smoke_server_accept_active(server, &peer);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    fixture->status = fixture->send(peer);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    atomic_store_explicit(&fixture->packet_sent,
                          1u,
                          memory_order_release);
    if (!smoke_integrity_wait_for_client_close(peer->fd))
    {
        fixture->status = LIBRDP_STATUS_TIMEOUT;
        goto cleanup;
    }
    atomic_store_explicit(&fixture->client_closed,
                          1u,
                          memory_order_release);
    fixture->status = LIBRDP_STATUS_OK;

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

static void smoke_graphics_channel_event(
    librdp_server_peer* peer,
    const librdp_server_channel_event* event,
    void* user_data)
{
    smoke_graphics_peer* fixture =
        (smoke_graphics_peer*)user_data;
    rdp_graphics_header header;

    (void)peer;
    if (!fixture || !event ||
        event->type != LIBRDP_SERVER_CHANNEL_EVENT_DYNAMIC_DATA ||
        event->dynamic_channel_id != 17u ||
        !event->data)
        return;
    if (rdp_graphics_parse_header(event->data,
                                  event->data_len,
                                  &header) != LIBRDP_STATUS_OK ||
        header.pdu_length != event->data_len)
        return;
    if (header.cmd_id == RDP_GRAPHICS_CMDID_CAPS_ADVERTISE)
    {
        (void)atomic_fetch_add_explicit(&fixture->caps_advertised,
                                        1u,
                                        memory_order_acq_rel);
    }
    else if (header.cmd_id ==
             RDP_GRAPHICS_CMDID_FRAME_ACKNOWLEDGE)
    {
        rdp_graphics_frame_ack acknowledgement;

        if (fixture->motion &&
            (rdp_graphics_parse_frame_ack(event->data,
                                          event->data_len,
                                          &acknowledgement) !=
                 LIBRDP_STATUS_OK ||
             acknowledgement.frame_id !=
                 fixture->last_ack_frame_id + 1u ||
             acknowledgement.total_frames_decoded !=
                 fixture->last_ack_total_frames + 1u))
        {
            fixture->acknowledgement_sequence_errors++;
        }
        else if (fixture->motion)
        {
            fixture->last_ack_frame_id =
                acknowledgement.frame_id;
            fixture->last_ack_total_frames =
                acknowledgement.total_frames_decoded;
        }
        (void)atomic_fetch_add_explicit(&fixture->frame_acknowledged,
                                        1u,
                                        memory_order_acq_rel);
    }
}

static librdp_status smoke_graphics_send_command(
    librdp_server_peer* peer,
    uint32_t channel_id,
    const rdp_buffer* command)
{
    rdp_buffer segmented;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !command)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&segmented);
    status = rdp_graphics_write_segmented_uncompressed(
        &segmented,
        command->data,
        command->length);
    if (status == LIBRDP_STATUS_OK)
    {
        status = librdp_server_peer_send_dynamic_channel_data(
            peer,
            channel_id,
            segmented.data,
            segmented.length);
    }
    rdp_buffer_free(&segmented);
    return status;
}

static librdp_status smoke_graphics_send_wire_bitmap(
    librdp_server_peer* peer,
    uint32_t channel_id,
    uint16_t surface_id,
    uint16_t codec_id,
    const rdp_graphics_rect16* dest_rect,
    const uint8_t* bitmap_data,
    uint32_t bitmap_data_len)
{
    rdp_buffer command;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !dest_rect ||
        (!bitmap_data && bitmap_data_len != 0u))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&command);
    status = rdp_graphics_write_wire_to_surface_1(
        &command,
        surface_id,
        codec_id,
        RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
        dest_rect,
        bitmap_data,
        bitmap_data_len);
    if (status == LIBRDP_STATUS_OK)
    {
        status = smoke_graphics_send_command(
            peer,
            channel_id,
            &command);
    }
    rdp_buffer_free(&command);
    return status;
}

/*
 * Select the newest AVC graphics capability used by the loopback peer. The
 * client rejects this confirmation unless its runtime decoder probe advertised
 * the matching AVC420, AVC444, and AVC444v2 paths.
 */
static librdp_status smoke_graphics_send_avc_caps(
    librdp_server_peer* peer,
    uint32_t channel_id)
{
    const rdp_graphics_capset selected = {
        RDP_GRAPHICS_CAPVERSION_107,
        RDP_GRAPHICS_CAPS_FLAG_SMALL_CACHE
    };
    rdp_buffer command;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&command);
    status = rdp_graphics_write_caps_confirm(
        &command,
        &selected);
    if (status == LIBRDP_STATUS_OK)
    {
        status = smoke_graphics_send_command(
            peer,
            channel_id,
            &command);
    }
    rdp_buffer_free(&command);
    return status;
}

/*
 * Serialize one valid H.264 intra frame with RDP AVC metadata and send it
 * through the real graphics channel. For AVC444, LC_BOTH carries independent
 * primary and auxiliary streams while LUMA and CHROMA exercise split updates.
 */
static librdp_status smoke_graphics_send_avc_wire(
    librdp_server_peer* peer,
    uint32_t channel_id,
    uint16_t surface_id,
    uint16_t codec_id,
    uint8_t lc,
    const rdp_graphics_rect16* rect)
{
    static const uint8_t h264_red_16x16[] = {
        0x00u, 0x00u, 0x00u, 0x01u, 0x67u, 0x42u, 0xc0u, 0x0au,
        0xddu, 0xecu, 0x04u, 0x40u, 0x00u, 0x00u, 0x03u, 0x00u,
        0x40u, 0x00u, 0x00u, 0x03u, 0x00u, 0xa3u, 0xc4u, 0x89u,
        0xe0u, 0x00u, 0x00u, 0x00u, 0x01u, 0x68u, 0xceu, 0x0fu,
        0xc8u, 0x00u, 0x00u, 0x01u, 0x65u, 0x88u, 0x84u, 0x3au,
        0x11u, 0x8au, 0x00u, 0x02u, 0x18u, 0xf1u, 0xc0u, 0x00u,
        0x40u, 0xf6u, 0x38u, 0x00u, 0x08u, 0x79u, 0x60u
    };
    static const uint8_t quant_quality[] = {
        0x45u, 100u
    };
    rdp_graphics_avc420_stream avc420;
    rdp_graphics_avc444_stream avc444;
    rdp_buffer rect_data;
    rdp_buffer payload;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !rect)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (codec_id != RDP_GRAPHICS_CODECID_AVC420 &&
        codec_id != RDP_GRAPHICS_CODECID_AVC444 &&
        codec_id != RDP_GRAPHICS_CODECID_AVC444V2)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    if (codec_id != RDP_GRAPHICS_CODECID_AVC420 &&
        (lc == RDP_GRAPHICS_AVC444_LC_INVALID ||
         lc > RDP_GRAPHICS_AVC444_LC_CHROMA))
        return LIBRDP_STATUS_INVALID_ARGUMENT;

    memset(&avc420, 0, sizeof(avc420));
    memset(&avc444, 0, sizeof(avc444));
    rdp_buffer_init(&rect_data);
    rdp_buffer_init(&payload);
    status = rdp_graphics_write_rect16(&rect_data, rect);
    if (status == LIBRDP_STATUS_OK)
    {
        avc420.meta.rect_count = 1u;
        avc420.meta.rects = rect_data.data;
        avc420.meta.rects_len = rect_data.length;
        avc420.meta.quant_quality = quant_quality;
        avc420.meta.quant_quality_len =
            sizeof(quant_quality);
        avc420.bitstream = h264_red_16x16;
        avc420.bitstream_len = sizeof(h264_red_16x16);
        if (codec_id == RDP_GRAPHICS_CODECID_AVC420)
        {
            status = rdp_graphics_write_avc420_stream(
                &payload,
                &avc420);
        }
        else
        {
            avc444.lc = lc;
            avc444.has_stream1 = 1u;
            avc444.stream1 = avc420;
            if (lc == RDP_GRAPHICS_AVC444_LC_BOTH)
            {
                avc444.has_stream2 = 1u;
                avc444.stream2 = avc420;
            }
            status = rdp_graphics_write_avc444_stream(
                &payload,
                &avc444);
        }
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = smoke_graphics_send_wire_bitmap(
            peer,
            channel_id,
            surface_id,
            codec_id,
            rect,
            payload.data,
            (uint32_t)payload.length);
    }
    rdp_buffer_free(&payload);
    rdp_buffer_free(&rect_data);
    return status;
}

typedef enum smoke_progressive_pass
{
    SMOKE_PROGRESSIVE_FIRST = 1,
    SMOKE_PROGRESSIVE_UPGRADE = 2
} smoke_progressive_pass;

/*
 * Build a complete progressive frame around one zero-coefficient tile. The
 * first pass establishes codec state; upgrade passes carry no coefficient
 * changes so framebuffer stability and cache lifetime can be checked exactly.
 */
static librdp_status smoke_graphics_build_progressive_frame(
    rdp_buffer* stream,
    uint32_t frame_index,
    smoke_progressive_pass pass)
{
    static const uint8_t base_quant[] = {
        0x11u, 0x11u, 0x11u, 0x11u, 0x11u
    };
    static const uint8_t progressive_quant[] = {
        100u,
        0u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u
    };
    const rdp_graphics_rect16 rect = {
        0u, 0u, 64u, 64u
    };
    rdp_graphics_progressive_context context;
    rdp_graphics_progressive_frame_begin frame_begin;
    rdp_graphics_progressive_region region;
    rdp_buffer rects;
    rdp_buffer tiles;
    rdp_buffer zeroes;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!stream ||
        (pass != SMOKE_PROGRESSIVE_FIRST &&
         pass != SMOKE_PROGRESSIVE_UPGRADE))
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&context, 0, sizeof(context));
    memset(&frame_begin, 0, sizeof(frame_begin));
    memset(&region, 0, sizeof(region));
    rdp_buffer_init(&rects);
    rdp_buffer_init(&tiles);
    rdp_buffer_init(&zeroes);

    status = rdp_graphics_progressive_write_region_rect(
        &rects,
        &rect);
    if (status == LIBRDP_STATUS_OK &&
        pass == SMOKE_PROGRESSIVE_FIRST)
    {
        rdp_graphics_progressive_tile_first tile;

        memset(&tile, 0, sizeof(tile));
        status = rdp_rfx_rlgr_write_zeroes(
            &zeroes,
            RDP_RFX_TILE_COEFFICIENTS);
        tile.block_type =
            RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_FIRST;
        tile.progressive_quality = 0u;
        tile.y_len = (uint16_t)zeroes.length;
        tile.cb_len = (uint16_t)zeroes.length;
        tile.cr_len = (uint16_t)zeroes.length;
        tile.y_data = zeroes.data;
        tile.cb_data = zeroes.data;
        tile.cr_data = zeroes.data;
        if (status == LIBRDP_STATUS_OK)
        {
            status = rdp_graphics_progressive_write_tile_first(
                &tiles,
                &tile);
        }
    }
    else if (status == LIBRDP_STATUS_OK)
    {
        rdp_graphics_progressive_tile_upgrade tile;

        memset(&tile, 0, sizeof(tile));
        tile.block_type =
            RDP_GRAPHICS_PROGRESSIVE_BLOCK_TILE_UPGRADE;
        tile.progressive_quality = 0u;
        status = rdp_graphics_progressive_write_tile_upgrade(
            &tiles,
            &tile);
    }

    context.context_id = 1u;
    context.tile_size = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    context.flags = 1u;
    frame_begin.frame_index = frame_index;
    frame_begin.region_count = 1u;
    region.tile_size = RDP_GRAPHICS_PROGRESSIVE_TILE_SIZE;
    region.rect_count = 1u;
    region.quant_count = 1u;
    region.progressive_quant_count = 1u;
    region.flags = 1u;
    region.tile_count = 1u;
    region.tile_data_size = (uint32_t)tiles.length;
    region.rects = rects.data;
    region.rects_len = rects.length;
    region.quant_values = base_quant;
    region.quant_values_len = sizeof(base_quant);
    region.progressive_quant_values = progressive_quant;
    region.progressive_quant_values_len =
        sizeof(progressive_quant);
    region.tiles = tiles.data;
    region.tiles_len = tiles.length;

    if (status == LIBRDP_STATUS_OK &&
        pass == SMOKE_PROGRESSIVE_FIRST)
    {
        status = rdp_graphics_progressive_write_context(
            stream,
            &context);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_graphics_progressive_write_frame_begin(
            stream,
            &frame_begin);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_graphics_progressive_write_region(
            stream,
            &region);
    }
    if (status == LIBRDP_STATUS_OK)
        status = rdp_graphics_progressive_write_frame_end(stream);
    rdp_buffer_free(&zeroes);
    rdp_buffer_free(&tiles);
    rdp_buffer_free(&rects);
    return status;
}

static librdp_status smoke_graphics_send_progressive_wire(
    librdp_server_peer* peer,
    uint32_t channel_id,
    uint16_t surface_id,
    uint32_t codec_context_id,
    uint32_t frame_index,
    smoke_progressive_pass pass)
{
    rdp_buffer stream;
    rdp_buffer command;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    rdp_buffer_init(&stream);
    rdp_buffer_init(&command);
    status = smoke_graphics_build_progressive_frame(
        &stream,
        frame_index,
        pass);
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_graphics_write_wire_to_surface_2(
            &command,
            surface_id,
            RDP_GRAPHICS_CODECID_CAPROGRESSIVE,
            codec_context_id,
            RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
            stream.data,
            (uint32_t)stream.length);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = smoke_graphics_send_command(
            peer,
            channel_id,
            &command);
    }
    rdp_buffer_free(&command);
    rdp_buffer_free(&stream);
    return status;
}

/* Derive distinct in-bounds geometry for every motion frame. */
static void smoke_graphics_motion_rect(uint32_t frame_index,
                                       librdp_rect* rect)
{
    uint32_t horizontal_span = 0u;
    uint32_t vertical_span = 0u;

    if (!rect)
        return;
    rect->width = 24u + ((frame_index * 5u) % 37u);
    rect->height = 18u + ((frame_index * 7u) % 31u);
    horizontal_span = SMOKE_WIDTH - rect->width + 1u;
    vertical_span = SMOKE_HEIGHT - rect->height + 1u;
    rect->x = (frame_index * 13u) % horizontal_span;
    rect->y = (frame_index * 11u) % vertical_span;
}

/*
 * Produce an opaque non-black desktop pattern. Every pixel is intentional, so
 * zero-filled holes and stale rows cannot accidentally match the reference.
 */
static void smoke_graphics_motion_background(uint8_t* pixels)
{
    uint32_t y = 0u;
    uint32_t x = 0u;

    if (!pixels)
        return;
    for (y = 0u; y < SMOKE_HEIGHT; y++)
    {
        for (x = 0u; x < SMOKE_WIDTH; x++)
        {
            size_t offset =
                (((size_t)y * SMOKE_WIDTH) + x) * 4u;

            pixels[offset] =
                (uint8_t)(1u + ((x * 3u + y * 5u) % 250u));
            pixels[offset + 1u] =
                (uint8_t)(1u + ((x * 7u + y * 11u) % 250u));
            pixels[offset + 2u] =
                (uint8_t)(1u + ((x * 13u + y * 17u) % 250u));
            pixels[offset + 3u] = 0xffu;
        }
    }
}

/* Build the complete reference image represented by one partial-update frame. */
static void smoke_graphics_motion_frame(const uint8_t* background,
                                        uint32_t frame_index,
                                        uint8_t* pixels,
                                        librdp_rect* rect)
{
    uint32_t y = 0u;
    uint32_t x = 0u;

    if (!background || !pixels || !rect)
        return;
    memcpy(pixels, background, SMOKE_PIXEL_BYTES);
    smoke_graphics_motion_rect(frame_index, rect);
    for (y = 0u; y < rect->height; y++)
    {
        for (x = 0u; x < rect->width; x++)
        {
            size_t offset =
                (((size_t)(rect->y + y) * SMOKE_WIDTH) +
                 rect->x + x) *
                4u;

            pixels[offset] = (uint8_t)(
                1u + ((frame_index * 17u + x * 3u + y) %
                      250u));
            pixels[offset + 1u] = (uint8_t)(
                1u + ((frame_index * 19u + x + y * 5u) %
                      250u));
            pixels[offset + 2u] = (uint8_t)(
                1u + ((frame_index * 23u + x * 7u + y * 11u) %
                      250u));
            pixels[offset + 3u] = 0xffu;
        }
    }
}

/*
 * Wait for one exact frame acknowledgement before allowing the producer to
 * mutate the next frame. This creates an observable stable point for every
 * full-frame comparison in the client thread.
 */
static librdp_status smoke_graphics_wait_for_frame_ack(
    librdp_server_peer* peer,
    smoke_graphics_peer* fixture,
    uint32_t frame_id,
    unsigned int expected_acknowledgements)
{
    uint32_t pending_frames = 0u;
    uint32_t last_ack_frame_id = 0u;
    unsigned int attempt = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !fixture || frame_id == 0u ||
        expected_acknowledgements == 0u)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (attempt = 0u; attempt < SMOKE_PUMP_LIMIT; attempt++)
    {
        status = librdp_server_peer_run_once(peer, 20);
        if (status != LIBRDP_STATUS_OK &&
            status != LIBRDP_STATUS_TIMEOUT)
            return status;
        status = librdp_server_peer_get_graphics_frame_state(
            peer,
            &pending_frames,
            NULL,
            &last_ack_frame_id);
        if (status != LIBRDP_STATUS_OK)
            return status;
        if (pending_frames == 0u &&
            last_ack_frame_id == frame_id &&
            atomic_load_explicit(&fixture->frame_acknowledged,
                                 memory_order_acquire) ==
                expected_acknowledgements)
            return LIBRDP_STATUS_OK;
    }
    return LIBRDP_STATUS_TIMEOUT;
}

/*
 * Exercise a long sequence of partial updates that models a moving, resizing
 * window with animated contents. Old bounds are restored from the background
 * before new bounds are drawn, and every frame is acknowledged independently.
 */
static librdp_status smoke_graphics_run_motion(
    librdp_server_peer* peer,
    smoke_graphics_peer* fixture,
    rdp_buffer* command,
    uint32_t* final_frame_id)
{
    uint8_t* background = NULL;
    uint8_t* frame = NULL;
    librdp_rect old_rect = {0u, 0u, 0u, 0u};
    librdp_rect current_rect;
    uint32_t frame_index = 0u;
    uint32_t frame_id = 0u;
    const uint32_t stride = SMOKE_WIDTH * 4u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !fixture || !command || !final_frame_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *final_frame_id = 0u;
    background = (uint8_t*)malloc(SMOKE_PIXEL_BYTES);
    frame = (uint8_t*)malloc(SMOKE_PIXEL_BYTES);
    if (!background || !frame)
    {
        status = LIBRDP_STATUS_NO_MEMORY;
        goto cleanup;
    }
    smoke_graphics_motion_background(background);
    status = librdp_server_peer_send_graphics_reset(
        peer,
        17u,
        SMOKE_WIDTH,
        SMOKE_HEIGHT);
    if (status == LIBRDP_STATUS_OK)
    {
        status = librdp_server_peer_send_graphics_create_surface(
            peer,
            17u,
            1u,
            SMOKE_WIDTH,
            SMOKE_HEIGHT,
            RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_graphics_write_map_surface_to_output(
            command,
            1u,
            0u,
            0u);
    }
    if (status == LIBRDP_STATUS_OK)
        status = smoke_graphics_send_command(peer, 17u, command);
    command->length = 0u;

    for (frame_index = 0u;
         status == LIBRDP_STATUS_OK &&
         frame_index < SMOKE_GRAPHICS_MOTION_FRAME_COUNT;
         frame_index++)
    {
        smoke_graphics_motion_frame(background,
                                    frame_index,
                                    frame,
                                    &current_rect);
        status = librdp_server_peer_send_graphics_start_frame(
            peer,
            17u,
            1000u + frame_index * 16u,
            &frame_id);
        if (status == LIBRDP_STATUS_OK && frame_index == 0u)
        {
            status =
                librdp_server_peer_send_graphics_bitmap_bgra32(
                    peer,
                    17u,
                    1u,
                    0u,
                    0u,
                    SMOKE_WIDTH,
                    SMOKE_HEIGHT,
                    stride,
                    frame);
        }
        else if (status == LIBRDP_STATUS_OK)
        {
            size_t old_offset =
                (((size_t)old_rect.y * SMOKE_WIDTH) +
                 old_rect.x) *
                4u;

            status =
                librdp_server_peer_send_graphics_bitmap_bgra32(
                    peer,
                    17u,
                    1u,
                    old_rect.x,
                    old_rect.y,
                    old_rect.width,
                    old_rect.height,
                    stride,
                    background + old_offset);
        }
        if (status == LIBRDP_STATUS_OK && frame_index > 0u)
        {
            size_t current_offset =
                (((size_t)current_rect.y * SMOKE_WIDTH) +
                 current_rect.x) *
                4u;

            status =
                librdp_server_peer_send_graphics_bitmap_bgra32(
                    peer,
                    17u,
                    1u,
                    current_rect.x,
                    current_rect.y,
                    current_rect.width,
                    current_rect.height,
                    stride,
                    frame + current_offset);
        }
        if (status == LIBRDP_STATUS_OK)
        {
            status = librdp_server_peer_send_graphics_end_frame(
                peer,
                17u,
                frame_id);
        }
        if (status == LIBRDP_STATUS_OK)
        {
            status = smoke_graphics_wait_for_frame_ack(
                peer,
                fixture,
                frame_id,
                (unsigned int)frame_index + 1u);
        }
        old_rect = current_rect;
    }
    if (status == LIBRDP_STATUS_OK)
        *final_frame_id = frame_id;

cleanup:
    free(frame);
    free(background);
    return status;
}

/*
 * Hold one frame credit in the client presenter, prove that the server rejects
 * another frame while the credit is outstanding, then continue after the
 * matching acknowledgement releases it.
 */
static librdp_status smoke_graphics_run_backpressure(
    librdp_server_peer* peer,
    smoke_graphics_peer* fixture,
    rdp_buffer* command,
    uint32_t* final_frame_id)
{
    uint32_t first_frame_id = 0u;
    uint32_t second_frame_id = 0u;
    uint32_t rejected_frame_id = 0u;
    uint32_t pending_frames = 0u;
    uint32_t frame_limit = 0u;
    uint32_t last_ack_frame_id = 0u;
    uint64_t first_frame_end_ns = 0u;
    unsigned int attempt = 0u;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer || !fixture || !command || !final_frame_id)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *final_frame_id = 0u;
    status = librdp_server_peer_send_graphics_reset(
        peer,
        17u,
        SMOKE_WIDTH,
        SMOKE_HEIGHT);
    if (status == LIBRDP_STATUS_OK)
    {
        status = librdp_server_peer_send_graphics_create_surface(
            peer,
            17u,
            1u,
            64u,
            64u,
            RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = rdp_graphics_write_map_surface_to_output(
            command,
            1u,
            0u,
            0u);
    }
    if (status == LIBRDP_STATUS_OK)
        status = smoke_graphics_send_command(peer, 17u, command);
    command->length = 0u;
    if (status == LIBRDP_STATUS_OK)
    {
        status = librdp_server_peer_set_graphics_frame_queue_limit(
            peer,
            1u);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = librdp_server_peer_send_graphics_start_frame(
            peer,
            17u,
            1000u,
            &first_frame_id);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = smoke_graphics_send_progressive_wire(
            peer,
            17u,
            1u,
            83u,
            1u,
            SMOKE_PROGRESSIVE_FIRST);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = librdp_server_peer_send_graphics_end_frame(
            peer,
            17u,
            first_frame_id);
    }
    if (status != LIBRDP_STATUS_OK)
        return status;
    first_frame_end_ns = smoke_now_ns();
    status = librdp_server_peer_get_graphics_frame_state(
        peer,
        &pending_frames,
        &frame_limit,
        &last_ack_frame_id);
    if (status != LIBRDP_STATUS_OK ||
        pending_frames != 1u ||
        frame_limit != 1u ||
        last_ack_frame_id != 0u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    fixture->maximum_pending_frames = pending_frames;
    status = librdp_server_peer_send_graphics_start_frame(
        peer,
        17u,
        2000u,
        &rejected_frame_id);
    if (status != LIBRDP_STATUS_LIMIT_EXCEEDED ||
        rejected_frame_id != 0u)
        return LIBRDP_STATUS_PROTOCOL_ERROR;
    fixture->backpressure_rejections++;

    for (attempt = 0u; attempt < SMOKE_PUMP_LIMIT; attempt++)
    {
        status = librdp_server_peer_run_once(peer, 20);
        if (status == LIBRDP_STATUS_TIMEOUT)
            fixture->acknowledgement_timeouts++;
        else if (status != LIBRDP_STATUS_OK)
            return status;
        status = librdp_server_peer_get_graphics_frame_state(
            peer,
            &pending_frames,
            &frame_limit,
            &last_ack_frame_id);
        if (status != LIBRDP_STATUS_OK ||
            pending_frames > frame_limit)
            return LIBRDP_STATUS_PROTOCOL_ERROR;
        if (pending_frames > fixture->maximum_pending_frames)
            fixture->maximum_pending_frames = pending_frames;
        if (pending_frames == 0u &&
            last_ack_frame_id == first_frame_id)
            break;
    }
    if (attempt == SMOKE_PUMP_LIMIT)
        return LIBRDP_STATUS_TIMEOUT;
    fixture->first_ack_delay_ns =
        smoke_now_ns() - first_frame_end_ns;

    status = librdp_server_peer_send_graphics_start_frame(
        peer,
        17u,
        2000u,
        &second_frame_id);
    if (status == LIBRDP_STATUS_OK)
    {
        status = smoke_graphics_send_progressive_wire(
            peer,
            17u,
            1u,
            83u,
            2u,
            SMOKE_PROGRESSIVE_UPGRADE);
    }
    if (status == LIBRDP_STATUS_OK)
    {
        status = librdp_server_peer_send_graphics_end_frame(
            peer,
            17u,
            second_frame_id);
    }
    if (status == LIBRDP_STATUS_OK)
        *final_frame_id = second_frame_id;
    return status;
}

/*
 * Drive one active peer through a complete RDPGFX surface and frame lifecycle.
 * The listener remains owned by the caller so a second generation can verify
 * reconnect cleanup against the same endpoint.
 */
static librdp_status smoke_graphics_run_connection(
    librdp_server* server,
    smoke_graphics_peer* fixture,
    unsigned int connection)
{
    static const uint8_t planar_no_alpha[] = {
        RDP_PLANAR_FORMAT_NO_ALPHA,
        0x10u, 0x20u,
        0x30u, 0x40u,
        0x50u, 0x60u
    };
    static const uint8_t uncompressed_pixels[] = {
        0x70u, 0x80u, 0x90u, 0x01u,
        0xa0u, 0xb0u, 0xc0u, 0x02u
    };
    static const uint8_t multi_surface_left[] = {
        0x01u, 0x02u, 0x03u, 0x11u,
        0x04u, 0x05u, 0x06u, 0x22u,
        0x07u, 0x08u, 0x09u, 0x33u,
        0x0au, 0x0bu, 0x0cu, 0x44u
    };
    static const uint8_t multi_surface_right[] = {
        0x10u, 0x20u, 0x30u, 0x55u,
        0x40u, 0x50u, 0x60u, 0x66u,
        0x70u, 0x80u, 0x90u, 0x77u,
        0xa0u, 0xb0u, 0xc0u, 0x88u
    };
    static const uint8_t clear_residual[] = {
        0x00u, 0x00u,
        0x04u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x01u, 0x02u, 0x03u, 0x04u
    };
    static const uint8_t clear_band_store[] = {
        0x04u, 0x02u,
        0x04u, 0x00u, 0x00u, 0x00u,
        0x13u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x04u,
        0x01u, 0x00u, 0x01u, 0x00u,
        0x00u, 0x00u, 0x01u, 0x00u,
        0x0au, 0x14u, 0x1eu,
        0x00u, 0x02u,
        0x01u, 0x02u, 0x03u,
        0x04u, 0x05u, 0x06u
    };
    static const uint8_t clear_band_reuse[] = {
        0x00u, 0x03u,
        0x04u, 0x00u, 0x00u, 0x00u,
        0x0du, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x04u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x01u, 0x00u,
        0x0au, 0x14u, 0x1eu,
        0x00u, 0x80u
    };
    static const uint8_t clear_glyph_store[] = {
        0x01u, 0x05u,
        0x02u, 0x00u,
        0x04u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x09u, 0x08u, 0x07u, 0x04u
    };
    static const uint8_t clear_glyph_reuse[] = {
        0x03u, 0x06u,
        0x02u, 0x00u
    };
    static const uint8_t clear_glyph_reset_store[] = {
        0x05u, 0x07u,
        0x02u, 0x00u,
        0x04u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x05u, 0x06u, 0x07u, 0x04u
    };
    static const uint8_t clear_band_after_reset[] = {
        0x00u, 0x08u,
        0x04u, 0x00u, 0x00u, 0x00u,
        0x0du, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x04u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x01u, 0x00u,
        0x0au, 0x14u, 0x1eu,
        0x0au, 0x80u
    };
    const rdp_graphics_rect16 planar_rect = {
        0u, 0u, 2u, 1u
    };
    librdp_server_peer* peer = NULL;
    rdp_buffer command;
    uint32_t frame_id = 0u;
    uint32_t pending_frames = 0u;
    uint32_t last_ack_frame_id = 0u;
    unsigned int attempt = 0u;

    if (!server || !fixture)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    fixture->status = LIBRDP_STATUS_TIMEOUT;
    rdp_buffer_init(&command);
    fixture->status = smoke_server_accept_active(server, &peer);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    (void)atomic_fetch_add_explicit(&fixture->connections,
                                    1u,
                                    memory_order_acq_rel);
    fixture->status = librdp_server_peer_set_channel_callback(
        peer,
        smoke_graphics_channel_event,
        fixture);
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    for (attempt = 0u; attempt < SMOKE_PUMP_LIMIT; attempt++)
    {
        fixture->status = librdp_server_peer_open_dynamic_channel(
            peer,
            17u,
            0u,
            RDP_GRAPHICS_PIPELINE_CHANNEL_NAME);
        if (fixture->status == LIBRDP_STATUS_OK)
            break;
        if (fixture->status != LIBRDP_STATUS_STATE)
            goto cleanup;
        fixture->status = librdp_server_peer_run_once(peer, 20);
        if (fixture->status != LIBRDP_STATUS_OK &&
            fixture->status != LIBRDP_STATUS_TIMEOUT)
            goto cleanup;
    }
    if (attempt == SMOKE_PUMP_LIMIT)
    {
        fixture->status = LIBRDP_STATUS_TIMEOUT;
        goto cleanup;
    }
    for (attempt = 0u;
         attempt < SMOKE_PUMP_LIMIT &&
         atomic_load_explicit(&fixture->caps_advertised,
                              memory_order_acquire) <= connection;
         attempt++)
    {
        fixture->status = librdp_server_peer_run_once(peer, 20);
        if (fixture->status != LIBRDP_STATUS_OK &&
            fixture->status != LIBRDP_STATUS_TIMEOUT)
            goto cleanup;
    }
    if (atomic_load_explicit(&fixture->caps_advertised,
                             memory_order_acquire) <= connection)
    {
        fixture->status = LIBRDP_STATUS_TIMEOUT;
        goto cleanup;
    }
    fixture->status = fixture->avc
                          ? smoke_graphics_send_avc_caps(peer, 17u)
                          : librdp_server_peer_send_graphics_default_caps(
                                peer,
                                17u);
    if (fixture->backpressure)
    {
        fixture->status = smoke_graphics_run_backpressure(
            peer,
            fixture,
            &command,
            &frame_id);
    }
    else if (fixture->motion)
    {
        fixture->status = smoke_graphics_run_motion(
            peer,
            fixture,
            &command,
            &frame_id);
    }
    else if (fixture->progressive)
    {
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_reset(
                    peer,
                    17u,
                    SMOKE_WIDTH,
                    SMOKE_HEIGHT);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_create_surface(
                    peer,
                    17u,
                    1u,
                    64u,
                    64u,
                    RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                rdp_graphics_write_map_surface_to_output(
                    &command,
                    1u,
                    0u,
                    0u);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status = smoke_graphics_send_command(
                peer,
                17u,
                &command);
        }
        command.length = 0u;
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_start_frame(
                    peer,
                    17u,
                    1000u,
                    &frame_id);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                smoke_graphics_send_progressive_wire(
                    peer,
                    17u,
                    1u,
                    73u,
                    1u,
                    SMOKE_PROGRESSIVE_FIRST);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                smoke_graphics_send_progressive_wire(
                    peer,
                    17u,
                    1u,
                    79u,
                    2u,
                    SMOKE_PROGRESSIVE_FIRST);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                smoke_graphics_send_progressive_wire(
                    peer,
                    17u,
                    1u,
                    73u,
                    3u,
                    SMOKE_PROGRESSIVE_UPGRADE);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                rdp_graphics_write_delete_encoding_context(
                    &command,
                    1u,
                    73u);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status = smoke_graphics_send_command(
                peer,
                17u,
                &command);
        }
        command.length = 0u;
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                smoke_graphics_send_progressive_wire(
                    peer,
                    17u,
                    1u,
                    79u,
                    4u,
                    SMOKE_PROGRESSIVE_UPGRADE);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                smoke_graphics_send_progressive_wire(
                    peer,
                    17u,
                    1u,
                    73u,
                    5u,
                    SMOKE_PROGRESSIVE_UPGRADE);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_end_frame(
                    peer,
                    17u,
                    frame_id);
        }
    }
    else if (fixture->avc)
    {
        const rdp_graphics_rect16 full_rect = {
            0u, 0u, 16u, 16u
        };
        const rdp_graphics_rect16 partial_rect = {
            1u, 1u, 16u, 16u
        };
        uint8_t background[
            SMOKE_AVC_SURFACE_DIMENSION *
            SMOKE_AVC_SURFACE_DIMENSION * 4u];
        size_t pixel_index = 0u;
        uint16_t surface_index = 0u;

        for (pixel_index = 0u;
             pixel_index <
                 (size_t)SMOKE_AVC_SURFACE_DIMENSION *
                     SMOKE_AVC_SURFACE_DIMENSION;
             pixel_index++)
        {
            background[pixel_index * 4u] = 0x11u;
            background[pixel_index * 4u + 1u] = 0x22u;
            background[pixel_index * 4u + 2u] = 0x33u;
            background[pixel_index * 4u + 3u] = 0xffu;
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_reset(
                    peer,
                    17u,
                    SMOKE_WIDTH,
                    SMOKE_HEIGHT);
        }
        for (surface_index = 0u;
             fixture->status == LIBRDP_STATUS_OK &&
             surface_index < SMOKE_AVC_SURFACE_COUNT;
             surface_index++)
        {
            uint16_t surface_id =
                (uint16_t)(surface_index + 1u);
            uint32_t output_x =
                (uint32_t)(surface_index %
                           SMOKE_AVC_LAYOUT_COLUMNS) *
                (SMOKE_AVC_SURFACE_DIMENSION +
                 SMOKE_AVC_LAYOUT_GAP);
            uint32_t output_y =
                (uint32_t)(surface_index /
                           SMOKE_AVC_LAYOUT_COLUMNS) *
                (SMOKE_AVC_SURFACE_DIMENSION +
                 SMOKE_AVC_LAYOUT_GAP);

            fixture->status =
                librdp_server_peer_send_graphics_create_surface(
                    peer,
                    17u,
                    surface_id,
                    SMOKE_AVC_SURFACE_DIMENSION,
                    SMOKE_AVC_SURFACE_DIMENSION,
                    RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888);
            if (fixture->status == LIBRDP_STATUS_OK)
            {
                fixture->status =
                    rdp_graphics_write_map_surface_to_output(
                        &command,
                        surface_id,
                        output_x,
                        output_y);
            }
            if (fixture->status == LIBRDP_STATUS_OK)
            {
                fixture->status =
                    smoke_graphics_send_command(
                        peer,
                        17u,
                        &command);
            }
            command.length = 0u;
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_start_frame(
                    peer,
                    17u,
                    1000u,
                    &frame_id);
        }
        for (surface_index = 0u;
             fixture->status == LIBRDP_STATUS_OK &&
             surface_index < SMOKE_AVC_SURFACE_COUNT;
             surface_index++)
        {
            fixture->status =
                librdp_server_peer_send_graphics_bitmap_bgra32(
                    peer,
                    17u,
                    (uint16_t)(surface_index + 1u),
                    0u,
                    0u,
                    SMOKE_AVC_SURFACE_DIMENSION,
                    SMOKE_AVC_SURFACE_DIMENSION,
                    SMOKE_AVC_SURFACE_DIMENSION * 4u,
                    background);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status = smoke_graphics_send_avc_wire(
                peer,
                17u,
                1u,
                RDP_GRAPHICS_CODECID_AVC420,
                RDP_GRAPHICS_AVC444_LC_INVALID,
                &full_rect);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status = smoke_graphics_send_avc_wire(
                peer,
                17u,
                2u,
                RDP_GRAPHICS_CODECID_AVC420,
                RDP_GRAPHICS_AVC444_LC_INVALID,
                &partial_rect);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status = smoke_graphics_send_avc_wire(
                peer,
                17u,
                3u,
                RDP_GRAPHICS_CODECID_AVC444,
                RDP_GRAPHICS_AVC444_LC_BOTH,
                &full_rect);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status = smoke_graphics_send_avc_wire(
                peer,
                17u,
                4u,
                RDP_GRAPHICS_CODECID_AVC444,
                RDP_GRAPHICS_AVC444_LC_LUMA,
                &partial_rect);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status = smoke_graphics_send_avc_wire(
                peer,
                17u,
                4u,
                RDP_GRAPHICS_CODECID_AVC444,
                RDP_GRAPHICS_AVC444_LC_CHROMA,
                &partial_rect);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status = smoke_graphics_send_avc_wire(
                peer,
                17u,
                5u,
                RDP_GRAPHICS_CODECID_AVC444V2,
                RDP_GRAPHICS_AVC444_LC_BOTH,
                &full_rect);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status = smoke_graphics_send_avc_wire(
                peer,
                17u,
                6u,
                RDP_GRAPHICS_CODECID_AVC444V2,
                RDP_GRAPHICS_AVC444_LC_LUMA,
                &partial_rect);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status = smoke_graphics_send_avc_wire(
                peer,
                17u,
                6u,
                RDP_GRAPHICS_CODECID_AVC444V2,
                RDP_GRAPHICS_AVC444_LC_CHROMA,
                &partial_rect);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_end_frame(
                    peer,
                    17u,
                    frame_id);
        }
    }
    else if (fixture->clearcodec)
    {
        const uint8_t* payloads[] = {
            clear_residual,
            clear_band_store,
            clear_band_reuse,
            clear_glyph_store,
            clear_glyph_reuse,
            clear_glyph_reset_store,
            clear_glyph_reuse,
            clear_band_after_reset
        };
        const uint32_t payload_lengths[] = {
            (uint32_t)sizeof(clear_residual),
            (uint32_t)sizeof(clear_band_store),
            (uint32_t)sizeof(clear_band_reuse),
            (uint32_t)sizeof(clear_glyph_store),
            (uint32_t)sizeof(clear_glyph_reuse),
            (uint32_t)sizeof(clear_glyph_reset_store),
            (uint32_t)sizeof(clear_glyph_reuse),
            (uint32_t)sizeof(clear_band_after_reset)
        };
        size_t payload_index = 0u;

        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_reset(
                    peer,
                    17u,
                    SMOKE_WIDTH,
                    SMOKE_HEIGHT);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_create_surface(
                    peer,
                    17u,
                    1u,
                    16u,
                    2u,
                    RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                rdp_graphics_write_map_surface_to_output(
                    &command,
                    1u,
                    0u,
                    0u);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
            fixture->status = smoke_graphics_send_command(
                peer,
                17u,
                &command);
        command.length = 0u;
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_start_frame(
                    peer,
                    17u,
                    1000u,
                    &frame_id);
        }
        for (payload_index = 0u;
             fixture->status == LIBRDP_STATUS_OK &&
             payload_index <
                 sizeof(payloads) / sizeof(payloads[0]);
             payload_index++)
        {
            rdp_graphics_rect16 dest_rect;

            dest_rect.left = (uint16_t)(payload_index * 2u);
            dest_rect.top = 0u;
            dest_rect.right = (uint16_t)(dest_rect.left + 2u);
            dest_rect.bottom = 2u;
            fixture->status = smoke_graphics_send_wire_bitmap(
                peer,
                17u,
                1u,
                RDP_GRAPHICS_CODECID_CLEARCODEC,
                &dest_rect,
                payloads[payload_index],
                payload_lengths[payload_index]);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_end_frame(
                    peer,
                    17u,
                    frame_id);
        }
    }
    else if (fixture->multi_surface)
    {
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_reset(
                    peer,
                    17u,
                    SMOKE_WIDTH,
                    SMOKE_HEIGHT);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_create_surface(
                    peer,
                    17u,
                    1u,
                    2u,
                    2u,
                    RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_create_surface(
                    peer,
                    17u,
                    2u,
                    2u,
                    2u,
                    RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                rdp_graphics_write_map_surface_to_output(
                    &command,
                    1u,
                    0u,
                    0u);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
            fixture->status = smoke_graphics_send_command(
                peer,
                17u,
                &command);
        command.length = 0u;
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                rdp_graphics_write_map_surface_to_output(
                    &command,
                    2u,
                    2u,
                    0u);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
            fixture->status = smoke_graphics_send_command(
                peer,
                17u,
                &command);
        command.length = 0u;
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_start_frame(
                    peer,
                    17u,
                    1000u,
                    &frame_id);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_bitmap_bgra32(
                    peer,
                    17u,
                    1u,
                    0u,
                    0u,
                    2u,
                    2u,
                    8u,
                    multi_surface_left);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_bitmap_bgra32(
                    peer,
                    17u,
                    2u,
                    0u,
                    0u,
                    2u,
                    2u,
                    8u,
                    multi_surface_right);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_end_frame(
                    peer,
                    17u,
                    frame_id);
        }
    }
    else
    {
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_reset(
                    peer,
                    17u,
                    SMOKE_WIDTH + 1u,
                    SMOKE_HEIGHT + 1u);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_create_surface(
                    peer,
                    17u,
                    1u,
                    4u,
                    2u,
                    RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                rdp_graphics_write_map_surface_to_output(
                    &command,
                    1u,
                    0u,
                    0u);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status = smoke_graphics_send_command(
                peer,
                17u,
                &command);
        }
        command.length = 0u;
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_start_frame(
                    peer,
                    17u,
                    1000u,
                    &frame_id);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                rdp_graphics_write_wire_to_surface_1(
                    &command,
                    1u,
                    RDP_GRAPHICS_CODECID_PLANAR,
                    RDP_GRAPHICS_PIXEL_FORMAT_XRGB_8888,
                    &planar_rect,
                    planar_no_alpha,
                    (uint32_t)sizeof(planar_no_alpha));
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status = smoke_graphics_send_command(
                peer,
                17u,
                &command);
        }
        command.length = 0u;
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_bitmap_bgra32(
                    peer,
                    17u,
                    1u,
                    2u,
                    0u,
                    2u,
                    1u,
                    8u,
                    uncompressed_pixels);
        }
        if (fixture->status == LIBRDP_STATUS_OK)
        {
            fixture->status =
                librdp_server_peer_send_graphics_end_frame(
                    peer,
                    17u,
                    frame_id);
        }
    }
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    for (attempt = 0u; attempt < SMOKE_PUMP_LIMIT; attempt++)
    {
        fixture->status = librdp_server_peer_run_once(peer, 20);
        if (fixture->status != LIBRDP_STATUS_OK &&
            fixture->status != LIBRDP_STATUS_TIMEOUT)
            goto cleanup;
        fixture->status =
            librdp_server_peer_get_graphics_frame_state(
                peer,
                &pending_frames,
                NULL,
                &last_ack_frame_id);
        if (fixture->status != LIBRDP_STATUS_OK)
            goto cleanup;
        if (pending_frames == 0u &&
            last_ack_frame_id == frame_id &&
            atomic_load_explicit(&fixture->frame_acknowledged,
                                 memory_order_acquire) > connection)
            break;
    }
    if (attempt == SMOKE_PUMP_LIMIT)
    {
        fixture->status = LIBRDP_STATUS_TIMEOUT;
        goto cleanup;
    }
    if (fixture->avc)
    {
        uint16_t surface_id = 1u;

        for (surface_id = 1u;
             fixture->status == LIBRDP_STATUS_OK &&
             surface_id <= SMOKE_AVC_SURFACE_COUNT;
             surface_id++)
        {
            fixture->status =
                librdp_server_peer_send_graphics_delete_surface(
                    peer,
                    17u,
                    surface_id);
        }
    }
    else
    {
        fixture->status =
            librdp_server_peer_send_graphics_delete_surface(
                peer,
                17u,
                1u);
        if (fixture->status == LIBRDP_STATUS_OK &&
            fixture->multi_surface)
        {
            fixture->status =
                librdp_server_peer_send_graphics_delete_surface(
                    peer,
                    17u,
                    2u);
        }
    }
    if (fixture->status != LIBRDP_STATUS_OK)
        goto cleanup;
    (void)atomic_fetch_add_explicit(&fixture->frame_sent,
                                    1u,
                                    memory_order_acq_rel);
    if (!smoke_integrity_wait_for_client_close(peer->fd))
    {
        fixture->status = LIBRDP_STATUS_TIMEOUT;
        goto cleanup;
    }
    (void)atomic_fetch_add_explicit(&fixture->client_closed,
                                    1u,
                                    memory_order_acq_rel);
    fixture->status = LIBRDP_STATUS_OK;

cleanup:
    rdp_buffer_free(&command);
    if (peer)
    {
        (void)librdp_server_peer_close(peer);
        librdp_server_peer_free(peer);
    }
    return fixture->status;
}

/*
 * Exercise the complete public client/server RDPGFX path with deterministic
 * updates. Reconnect mode accepts two successive peers on one listener.
 */
static void* smoke_graphics_peer_main(void* user_data)
{
    smoke_graphics_peer* fixture =
        (smoke_graphics_peer*)user_data;
    librdp_server* server = NULL;
    unsigned int connection = 0u;
    unsigned int connection_count = 1u;

    if (!fixture)
        return NULL;
    fixture->status = LIBRDP_STATUS_TIMEOUT;
    server = librdp_server_new(&fixture->config);
    if (!server)
    {
        fixture->status = LIBRDP_STATUS_NO_MEMORY;
        return NULL;
    }
    fixture->status = librdp_server_listen(server);
    if (fixture->status == LIBRDP_STATUS_OK)
    {
        atomic_store_explicit(&fixture->port,
                              librdp_server_local_port(server),
                              memory_order_release);
        connection_count = fixture->reconnect ? 2u : 1u;
        for (connection = 0u;
             connection < connection_count;
             connection++)
        {
            fixture->status = smoke_graphics_run_connection(
                server,
                fixture,
                connection);
            if (fixture->status != LIBRDP_STATUS_OK)
                break;
        }
    }
    (void)librdp_server_close(server);
    librdp_server_free(server);
    return NULL;
}

static const uint8_t smoke_redirection_routing_token[] = {
    'r', 'o', 'u', 't', 'e', '=', 's', 'm', 'o', 'k', 'e', '\r', '\n'
};

/*
 * Send the same typed redirection through the security envelope selected by
 * the peer. Standard Security uses SEC_REDIRECTION_PKT; TLS uses the enhanced
 * Share Control PDU because the transport already supplies confidentiality.
 */
static librdp_status smoke_redirection_send(librdp_server_peer* peer,
                                            int enhanced)
{
    rdp_server_redirection_packet redirection;
    rdp_buffer packet;
    rdp_buffer secured;
    rdp_buffer mcs;
    librdp_status status = LIBRDP_STATUS_OK;

    if (!peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    memset(&redirection, 0, sizeof(redirection));
    redirection.session_id = 0x10203040u;
    redirection.redirection_flags =
        RDP_SERVER_REDIRECTION_LB_LOAD_BALANCE_INFO;
    redirection.load_balance_info.data =
        smoke_redirection_routing_token;
    redirection.load_balance_info.length =
        (uint32_t)sizeof(smoke_redirection_routing_token);
    rdp_buffer_init(&packet);
    rdp_buffer_init(&secured);
    rdp_buffer_init(&mcs);
    if (enhanced)
    {
        status = rdp_server_redirection_write_enhanced(
            &packet,
            (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
            &redirection,
            1,
            1);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_send_slowpath(peer, &packet);
    }
    else
    {
        if (!peer->standard_security_ready)
            status = LIBRDP_STATUS_STATE;
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_redirection_write_packet(
                &packet,
                &redirection,
                1);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_security_write_encrypted_pdu(
                &secured,
                &peer->standard_security,
                RDP_SEC_REDIRECTION_PKT,
                packet.data,
                packet.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_mcs_write_send_data_indication(
                &mcs,
                peer->user_id,
                (uint16_t)RDP_MCS_GLOBAL_CHANNEL_ID,
                secured.data,
                secured.length);
        if (status == LIBRDP_STATUS_OK)
            status = rdp_server_send_mcs_pdu(peer, &mcs);
    }
    rdp_buffer_free(&mcs);
    rdp_buffer_free(&secured);
    rdp_buffer_free(&packet);
    return status;
}

static librdp_status smoke_redirection_accept_active(
    smoke_redirection_peer* fixture,
    librdp_server* server,
    librdp_server_peer** peer)
{
    unsigned int attempt = 0u;
    librdp_status status = LIBRDP_STATUS_TIMEOUT;

    if (!fixture || !server || !peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    *peer = NULL;
    for (attempt = 0u;
         attempt < 500u &&
         atomic_load_explicit(&fixture->stop, memory_order_acquire) == 0u &&
         !*peer;
         attempt++)
    {
        status = librdp_server_accept(server, 20, peer);
        if (status != LIBRDP_STATUS_TIMEOUT)
            break;
    }
    if (!*peer)
        return status;
    for (attempt = 0u;
         attempt < 500u &&
         atomic_load_explicit(&fixture->stop, memory_order_acquire) == 0u;
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
    return LIBRDP_STATUS_TIMEOUT;
}

static int smoke_redirection_route_matches(
    const librdp_server_peer* peer)
{
    uint32_t required_cluster_flags =
        RDP_GCC_CLUSTER_REDIRECTION_SUPPORTED |
        RDP_GCC_CLUSTER_REDIRECTED_SESSION_ID_VALID;

    return peer &&
           peer->x224_routing_data.length ==
               sizeof(smoke_redirection_routing_token) &&
           memcmp(peer->x224_routing_data.data,
                  smoke_redirection_routing_token,
                  sizeof(smoke_redirection_routing_token)) == 0 &&
           (peer->client_cluster_flags & required_cluster_flags) ==
               required_cluster_flags &&
           peer->redirected_session_id == 0x10203040u;
}

static librdp_status smoke_redirection_wait_for_client_close(
    smoke_redirection_peer* fixture,
    librdp_server_peer* peer)
{
    unsigned int attempt = 0u;

    if (!fixture || !peer)
        return LIBRDP_STATUS_INVALID_ARGUMENT;
    for (attempt = 0u; attempt < 500u; attempt++)
    {
        librdp_status status =
            librdp_server_peer_run_once(peer, 20);

        if (status == LIBRDP_STATUS_CLOSED ||
            status == LIBRDP_STATUS_IO_ERROR ||
            librdp_server_peer_get_state(peer) ==
                LIBRDP_SERVER_PEER_CLOSED)
            return LIBRDP_STATUS_OK;
        if (status != LIBRDP_STATUS_OK &&
            status != LIBRDP_STATUS_TIMEOUT)
            return status;
    }
    return LIBRDP_STATUS_TIMEOUT;
}

/*
 * Accept successive loopback peers so the client reconnect happens while its
 * dispatch call is blocked in the connection state machine. The final peer is
 * held open until the client verifies success or rejects the bounded loop.
 */
static void* smoke_redirection_peer_main(void* user_data)
{
    smoke_redirection_peer* fixture =
        (smoke_redirection_peer*)user_data;
    librdp_server* server = NULL;
    librdp_server_peer* peer = NULL;
    unsigned int connection = 0u;
    unsigned int final_connection =
        RDP_SESSION_MAX_SERVER_REDIRECTS;

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
    if (!fixture->loop)
        final_connection = 1u;
    for (connection = 0u; connection <= final_connection; connection++)
    {
        fixture->status = smoke_redirection_accept_active(
            fixture,
            server,
            &peer);
        if (fixture->status != LIBRDP_STATUS_OK)
            goto cleanup;
        atomic_fetch_add_explicit(&fixture->connections,
                                  1u,
                                  memory_order_release);
        if (connection > 0u)
        {
            if (!smoke_redirection_route_matches(peer))
            {
                fixture->status = LIBRDP_STATUS_PROTOCOL_ERROR;
                goto cleanup;
            }
            atomic_store_explicit(&fixture->route_verified,
                                  1u,
                                  memory_order_release);
        }
        if (!fixture->loop && connection == final_connection)
            break;
        fixture->status = smoke_redirection_send(
            peer,
            fixture->enhanced);
        if (fixture->status != LIBRDP_STATUS_OK)
            goto cleanup;
        atomic_fetch_add_explicit(&fixture->redirects,
                                  1u,
                                  memory_order_release);
        fixture->status = smoke_redirection_wait_for_client_close(
            fixture,
            peer);
        if (fixture->status != LIBRDP_STATUS_OK)
            goto cleanup;
        (void)librdp_server_peer_close(peer);
        librdp_server_peer_free(peer);
        peer = NULL;
    }
    fixture->status = LIBRDP_STATUS_OK;
    while (atomic_load_explicit(&fixture->stop,
                                memory_order_acquire) == 0u)
    {
        struct timespec delay = {0, 10000000L};

        (void)nanosleep(&delay, NULL);
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

static void smoke_client_event(librdp_session* session,
                               const librdp_event* event,
                               void* user_data)
{
    smoke_client_events* events = (smoke_client_events*)user_data;

    if (!session || !events || !event)
        return;
    if (event->type == LIBRDP_EVENT_STATE_CHANGED)
    {
        events->state_events++;
        events->active =
            event->data.state.new_state == LIBRDP_SESSION_ACTIVE;
        if (events->active)
            events->active_seen = 1;
    }
    else if (event->type == LIBRDP_EVENT_SURFACE_INVALIDATED)
        events->surface_events++;
    else if (event->type == LIBRDP_EVENT_ERROR)
        events->error_events++;
    else if (events->clipboard_provider &&
             server_client_clipboard_provider_handle_client_event(
                 events->clipboard_provider,
                 session,
                 event))
    {
    }
    else if (event->type == LIBRDP_EVENT_CLIPBOARD_FORMATS &&
             events->clipboard_profile)
    {
        uint32_t index = 0u;
        int matched = 0;

        events->clipboard_format_events++;
        for (index = 0u;
             index < event->data.clipboard_formats.count;
             index++)
        {
            if (event->data.clipboard_formats.formats[index].format_id ==
                events->clipboard_profile->format_id)
            {
                matched = 1;
                break;
            }
        }
        if (!matched)
            events->clipboard_failures++;
        else if (!events->clipboard_data_requested)
        {
            if (librdp_session_clipboard_request_data(
                    session,
                    events->clipboard_profile->format_id) !=
                LIBRDP_STATUS_OK)
                events->clipboard_failures++;
            else
                events->clipboard_data_requested = 1;
        }
    }
    else if (event->type == LIBRDP_EVENT_CLIPBOARD_DATA &&
             events->clipboard_profile)
    {
        const librdp_clipboard_data_event* data =
            &event->data.clipboard_data;

        if (!data->ok ||
            data->format_id != events->clipboard_profile->format_id ||
            !server_client_clipboard_profile_validate_server_data(
                events->clipboard_profile,
                data->data,
                data->data_len))
        {
            events->clipboard_failures++;
            return;
        }
        events->clipboard_data_events++;
    }
    else if (event->type == LIBRDP_EVENT_CLIPBOARD_REQUEST &&
             events->clipboard_profile)
    {
        if (event->data.clipboard_request.format_id !=
            events->clipboard_profile->format_id)
            events->clipboard_failures++;
        events->clipboard_request_events++;
    }
}

static int smoke_clipboard_profile_complete(
    const server_client_clipboard_provider* provider,
    const smoke_client_events* events)
{
    if (!provider || !events || !events->clipboard_profile)
        return 0;
    if (server_client_clipboard_profile_is_file_transfer(
            events->clipboard_profile))
        return server_client_clipboard_provider_complete(provider);
    return events->clipboard_format_events > 0u &&
           events->clipboard_data_events == 1u &&
           events->clipboard_request_events == 1u &&
           events->clipboard_failures == 0u &&
           server_client_clipboard_provider_complete(provider);
}

static librdp_status smoke_client_pump(client_runtime* runtime)
{
    struct pollfd* fds = NULL;
    size_t count = 0u;
    int timeout_ms = 20;
    int ready = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    status = client_runtime_prepare_poll(runtime,
                                         NULL,
                                         0u,
                                         20,
                                         &fds,
                                         &count,
                                         &timeout_ms);
    if (status != LIBRDP_STATUS_OK)
        return status;
    do
    {
        ready = poll(fds, (nfds_t)count, timeout_ms);
    } while (ready < 0 && errno == EINTR);
    if (ready < 0)
        return LIBRDP_STATUS_IO_ERROR;
    return client_runtime_dispatch_poll(runtime, 16u);
}

static int smoke_wait_for_port(const atomic_uint* source, uint16_t* port)
{
    unsigned int attempt = 0u;
    struct timespec delay = {0, 10000000L};

    if (!source || !port)
        return 0;
    for (attempt = 0u; attempt < 500u; attempt++)
    {
        unsigned int value = atomic_load_explicit(source,
                                                  memory_order_acquire);

        if (value > 0u && value <= UINT16_MAX)
        {
            *port = (uint16_t)value;
            return 1;
        }
        (void)nanosleep(&delay, NULL);
    }
    return 0;
}

static int smoke_wait_for_counter(const atomic_uint* source,
                                  unsigned int expected)
{
    unsigned int attempt = 0u;
    struct timespec delay = {0, 1000000L};

    if (!source)
        return 0;
    for (attempt = 0u; attempt < 1000u; attempt++)
    {
        if (atomic_load_explicit(source,
                                 memory_order_acquire) >=
            expected)
            return 1;
        (void)nanosleep(&delay, NULL);
    }
    return 0;
}

static int smoke_join_path(char* destination,
                           size_t capacity,
                           const char* directory,
                           const char* name)
{
    int length = 0;

    if (!destination || capacity == 0u || !directory || !name)
        return 0;
    length = snprintf(destination,
                      capacity,
                      "%s/%s",
                      directory,
                      name);
    return length > 0 && (size_t)length < capacity;
}

static int smoke_write_file_data(const char* path,
                                 const uint8_t* data,
                                 size_t data_len)
{
    size_t offset = 0u;
    int fd = -1;
    int ok = 1;

    if (!path || (!data && data_len > 0u))
        return 0;
    fd = open(path,
              O_CREAT | O_EXCL | O_WRONLY,
              S_IRUSR | S_IWUSR);
    if (fd < 0)
        return 0;
    while (offset < data_len)
    {
        ssize_t written =
            write(fd, data + offset, data_len - offset);

        if (written > 0)
            offset += (size_t)written;
        else if (written < 0 && errno == EINTR)
            continue;
        else
        {
            ok = 0;
            break;
        }
    }
    if (close(fd) != 0)
        ok = 0;
    if (!ok)
        (void)unlink(path);
    return ok;
}

static int smoke_file_matches(const char* path,
                              const uint8_t* expected,
                              size_t expected_len)
{
    uint8_t buffer[64];
    size_t offset = 0u;
    int fd = -1;
    int ok = 1;

    if (!path || !expected || expected_len > sizeof(buffer))
        return 0;
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return 0;
    while (offset < expected_len)
    {
        ssize_t count =
            read(fd, buffer + offset, expected_len - offset);

        if (count > 0)
            offset += (size_t)count;
        else if (count < 0 && errno == EINTR)
            continue;
        else
        {
            ok = 0;
            break;
        }
    }
    if (ok)
    {
        uint8_t trailing = 0u;

        ok = read(fd, &trailing, 1u) == 0 &&
             memcmp(buffer, expected, expected_len) == 0;
    }
    if (close(fd) != 0)
        ok = 0;
    return ok;
}

/*
 * Build hostile filesystem objects without elevated privileges. A separate
 * read-only /dev mapping exercises the character-device case.
 */
static int smoke_drive_confinement_fixture_init(
    smoke_drive_confinement_fixture* fixture,
    const char* drive_root)
{
    struct sockaddr_un address;
    socklen_t address_len = 0u;
    size_t socket_path_len = 0u;
    int length = 0;

    if (!fixture || !drive_root)
        return 0;
    memset(fixture, 0, sizeof(*fixture));
    fixture->socket_fd = -1;
    length = snprintf(fixture->outside_directory,
                      sizeof(fixture->outside_directory),
                      "/tmp/librdp-drive-outside-%ld-XXXXXX",
                      (long)getpid());
    if (length < 0 ||
        (size_t)length >= sizeof(fixture->outside_directory) ||
        !mkdtemp(fixture->outside_directory) ||
        !smoke_join_path(fixture->outside_file,
                         sizeof(fixture->outside_file),
                         fixture->outside_directory,
                         "outside.txt") ||
        !smoke_join_path(fixture->outside_escape,
                         sizeof(fixture->outside_escape),
                         fixture->outside_directory,
                         "escaped.txt") ||
        !smoke_join_path(fixture->final_symlink,
                         sizeof(fixture->final_symlink),
                         drive_root,
                         "outside-link") ||
        !smoke_join_path(fixture->directory_symlink,
                         sizeof(fixture->directory_symlink),
                         drive_root,
                         "outside-directory-link") ||
        !smoke_join_path(fixture->fifo,
                         sizeof(fixture->fifo),
                         drive_root,
                         "pipe-node") ||
        !smoke_join_path(fixture->socket,
                         sizeof(fixture->socket),
                         drive_root,
                         "socket-node") ||
        !smoke_join_path(fixture->race,
                         sizeof(fixture->race),
                         drive_root,
                         "race.txt") ||
        !smoke_join_path(fixture->race_original,
                         sizeof(fixture->race_original),
                         drive_root,
                         "race-original.txt") ||
        !smoke_join_path(fixture->race_renamed,
                         sizeof(fixture->race_renamed),
                         drive_root,
                         "race-renamed.txt") ||
        !smoke_join_path(fixture->root_escape,
                         sizeof(fixture->root_escape),
                         drive_root,
                         "escaped.txt") ||
        !smoke_write_file_data(
            fixture->outside_file,
            smoke_drive_outside_data,
            sizeof(smoke_drive_outside_data) - 1u) ||
        !smoke_write_file_data(
            fixture->race,
            smoke_drive_race_original_data,
            sizeof(smoke_drive_race_original_data) - 1u) ||
        symlink(fixture->outside_file,
                fixture->final_symlink) != 0 ||
        symlink(fixture->outside_directory,
                fixture->directory_symlink) != 0 ||
        mkfifo(fixture->fifo, S_IRUSR | S_IWUSR) != 0)
        return 0;
    fixture->socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    socket_path_len = strlen(fixture->socket);
    if (fixture->socket_fd < 0 ||
        socket_path_len >= sizeof(address.sun_path))
        return 0;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path,
           fixture->socket,
           socket_path_len + 1u);
    address_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                              socket_path_len + 1u);
    return bind(fixture->socket_fd,
                (const struct sockaddr*)&address,
                address_len) == 0;
}

static void smoke_drive_confinement_fixture_clear(
    smoke_drive_confinement_fixture* fixture)
{
    if (!fixture)
        return;
    if (fixture->socket_fd >= 0)
    {
        (void)close(fixture->socket_fd);
        fixture->socket_fd = -1;
    }
    if (fixture->socket[0] != '\0')
        (void)unlink(fixture->socket);
    if (fixture->fifo[0] != '\0')
        (void)unlink(fixture->fifo);
    if (fixture->final_symlink[0] != '\0')
        (void)unlink(fixture->final_symlink);
    if (fixture->directory_symlink[0] != '\0')
        (void)unlink(fixture->directory_symlink);
    if (fixture->race[0] != '\0')
        (void)unlink(fixture->race);
    if (fixture->race_original[0] != '\0')
        (void)unlink(fixture->race_original);
    if (fixture->race_renamed[0] != '\0')
        (void)unlink(fixture->race_renamed);
    if (fixture->root_escape[0] != '\0')
        (void)unlink(fixture->root_escape);
    if (fixture->outside_escape[0] != '\0')
        (void)unlink(fixture->outside_escape);
    if (fixture->outside_file[0] != '\0')
        (void)unlink(fixture->outside_file);
    if (fixture->outside_directory[0] != '\0')
        (void)rmdir(fixture->outside_directory);
}

static int smoke_drive_confinement_swap_race(
    smoke_drive_confinement_fixture* fixture)
{
    if (!fixture || fixture->race_swapped ||
        rename(fixture->race, fixture->race_original) != 0)
        return 0;
    if (!smoke_write_file_data(
            fixture->race,
            smoke_drive_race_replacement_data,
            sizeof(smoke_drive_race_replacement_data) - 1u))
        return 0;
    fixture->race_swapped = 1;
    return 1;
}

static int smoke_drive_confinement_fixture_valid(
    const smoke_drive_confinement_fixture* fixture)
{
    struct stat st;

    if (!fixture || !fixture->race_swapped ||
        !smoke_file_matches(
            fixture->outside_file,
            smoke_drive_outside_data,
            sizeof(smoke_drive_outside_data) - 1u) ||
        !smoke_file_matches(
            fixture->race_original,
            smoke_drive_race_original_data,
            sizeof(smoke_drive_race_original_data) - 1u) ||
        !smoke_file_matches(
            fixture->race,
            smoke_drive_race_replacement_data,
            sizeof(smoke_drive_race_replacement_data) - 1u) ||
        access(fixture->race_renamed, F_OK) == 0 ||
        access(fixture->root_escape, F_OK) == 0 ||
        access(fixture->outside_escape, F_OK) == 0)
        return 0;
    memset(&st, 0, sizeof(st));
    if (lstat(fixture->final_symlink, &st) != 0 ||
        !S_ISLNK(st.st_mode))
        return 0;
    memset(&st, 0, sizeof(st));
    if (lstat(fixture->directory_symlink, &st) != 0 ||
        !S_ISLNK(st.st_mode))
        return 0;
    memset(&st, 0, sizeof(st));
    if (lstat(fixture->fifo, &st) != 0 ||
        !S_ISFIFO(st.st_mode))
        return 0;
    memset(&st, 0, sizeof(st));
    return lstat(fixture->socket, &st) == 0 &&
           S_ISSOCK(st.st_mode);
}

static int smoke_make_drive(char* directory,
                            size_t directory_size,
                            char* marker,
                            size_t marker_size)
{
    int fd = -1;
    int length = 0;
    static const char content[] = "temporary client drive\n";

    if (!directory || directory_size < 32u || !marker || marker_size < 48u)
        return 0;
    length = snprintf(directory,
                      directory_size,
                      "/tmp/librdp-drive-smoke-%ld-XXXXXX",
                      (long)getpid());
    if (length < 0 || (size_t)length >= directory_size || !mkdtemp(directory))
        return 0;
    length = snprintf(marker, marker_size, "%s/marker.txt", directory);
    if (length < 0 || (size_t)length >= marker_size)
    {
        (void)rmdir(directory);
        directory[0] = '\0';
        return 0;
    }
    fd = open(marker, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        (void)rmdir(directory);
        directory[0] = '\0';
        return 0;
    }
    if (write(fd, content, sizeof(content) - 1u) !=
        (ssize_t)(sizeof(content) - 1u))
    {
        (void)close(fd);
        (void)unlink(marker);
        (void)rmdir(directory);
        directory[0] = '\0';
        marker[0] = '\0';
        return 0;
    }
    if (close(fd) != 0)
    {
        (void)unlink(marker);
        (void)rmdir(directory);
        directory[0] = '\0';
        marker[0] = '\0';
        return 0;
    }
    return 1;
}

static int smoke_write_drive_file(const char* path)
{
    static const uint8_t content[] = "notify";
    int fd = -1;
    int ok = 0;

    if (!path)
        return 0;
    fd = open(path,
              O_CREAT | O_EXCL | O_WRONLY,
              S_IRUSR | S_IWUSR);
    if (fd < 0)
        return 0;
    ok = write(fd, content, sizeof(content) - 1u) ==
         (ssize_t)(sizeof(content) - 1u);
    if (close(fd) != 0)
        ok = 0;
    if (!ok)
        (void)unlink(path);
    return ok;
}

static int smoke_drive_limit_file_valid(const char* path)
{
    uint8_t data[sizeof(smoke_drive_limit_valid_data)] = {0};
    struct stat st;
    ssize_t count = 0;
    int fd = -1;
    int valid = 0;

    if (!path)
        return 0;
    memset(&st, 0, sizeof(st));
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return 0;
    count = pread(fd, data, sizeof(data), 0);
    valid = fstat(fd, &st) == 0 &&
            st.st_size == (off_t)sizeof(data) &&
            count == (ssize_t)sizeof(data) &&
            memcmp(data,
                   smoke_drive_limit_valid_data,
                   sizeof(data)) == 0;
    if (close(fd) != 0)
        valid = 0;
    return valid;
}

static int smoke_configure_security(server_host_config* host_config,
                                    librdp_settings* settings,
                                    librdp_security_mode security,
                                    const char* cert_path,
                                    const char* key_path,
                                    const smoke_nla_identity* identity)
{
    librdp_tls_policy tls_policy;

    host_config->server.security_mode = security;
    if (librdp_settings_set_security_mode(settings, security) !=
        LIBRDP_STATUS_OK)
        return 0;
    if (security == LIBRDP_SECURITY_STANDARD)
        return 1;
    host_config->server.tls_certificate_path = cert_path;
    host_config->server.tls_private_key_path = key_path;
    if (librdp_tls_policy_init(&tls_policy) != LIBRDP_STATUS_OK)
        return 0;
    tls_policy.mode = LIBRDP_TLS_POLICY_INSECURE_LAB;
    tls_policy.use_system_store = 0;
    if (librdp_settings_set_tls_policy(settings, &tls_policy) !=
        LIBRDP_STATUS_OK)
        return 0;
    if (security != LIBRDP_SECURITY_NLA)
        return 1;
    if (!identity || !identity->username || !identity->password)
        return 0;
    host_config->server.nla_username = identity->username;
    host_config->server.nla_password = identity->password;
    host_config->server.nla_domain = identity->domain;
    if (librdp_settings_set_username(settings, identity->username) !=
            LIBRDP_STATUS_OK ||
        librdp_settings_set_password(settings, identity->password) !=
            LIBRDP_STATUS_OK)
        return 0;
    return !identity->domain ||
           librdp_settings_set_domain(settings, identity->domain) ==
               LIBRDP_STATUS_OK;
}

/*
 * Complete one security profile through the public client API and application
 * server host. Every provider must cross a real protocol boundary before the
 * fixture accepts the run.
 */
static int smoke_run_profile_ex(
    librdp_security_mode security,
    librdp_status expected_connect_status,
    const smoke_nla_identity* identity,
    const char* bind_address,
    const char* target,
    const smoke_gateway_profile* gateway_profile,
    int exercise_output_control,
    int cancel_phase,
    const server_client_clipboard_profile* clipboard_profile,
    const smoke_drive_profile* drive_profile,
    smoke_auth_redirection* auth_redirection)
{
    char cert_path[128] = {0};
    char key_path[128] = {0};
    char gateway_cert_path[128] = {0};
    char gateway_key_path[128] = {0};
    char drive_directory[128] = {0};
    char drive_marker[160] = {0};
    char drive_created[160] = {0};
    char drive_renamed[160] = {0};
    char drive_notify_directory[160] = {0};
    char drive_notify_first[192] = {0};
    char drive_notify_late[192] = {0};
    char drive_limit_primary[160] = {0};
    char drive_limit_quaternary[160] = {0};
    char gateway_url[128] = {0};
    char* saved_curl_ca_bundle = NULL;
    static const uint8_t clipboard_data[] = {'s', 'm', 'o', 'k', 'e'};
    smoke_platform platform;
    smoke_host host_fixture;
    smoke_client_events events;
    smoke_nla_provider nla_provider;
    smoke_trace_capture trace_capture;
    smoke_drive_confinement_fixture drive_confinement;
    test_http_proxy proxy;
    test_http_proxy_config proxy_config;
    test_rdg_gateway rdg_gateway;
    test_rdg_gateway_config rdg_config;
    server_host_config host_config;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    server_client_clipboard_provider* clipboard_provider = NULL;
    librdp_gateway_config gateway_config;
    client_runtime runtime;
    librdp_trace_policy trace_policy;
    librdp_error_info error_info;
    librdp_key_event key;
    librdp_mouse_event mouse;
    librdp_status connect_status = LIBRDP_STATUS_OK;
    librdp_status terminal_status = LIBRDP_STATUS_OK;
    uint16_t port = 0u;
    uint16_t default_port = 0u;
    unsigned int cycle = 0u;
    unsigned int capture_before_refresh = 0u;
    unsigned int refresh_requests_before = 0u;
    unsigned int output_suppressions_before = 0u;
    unsigned int output_resumptions_before = 0u;
    unsigned int surface_events_before_resume = 0u;
    uint8_t initial_pixel[4] = {0};
    int clipboard_sent = 0;
    int curl_environment_changed = 0;
    int drive_directory_owned = 0;
    int input_sent = 0;
    int proxy_started = 0;
    int rdg_started = 0;
    int output_control_stage = 0;
    int thread_started = 0;
    int result = 1;
    const librdp_gateway_mode gateway_mode =
        gateway_profile
            ? gateway_profile->mode
            : LIBRDP_GATEWAY_DISABLED;
    const smoke_gateway_credentials gateway_credentials =
        gateway_profile
            ? gateway_profile->credentials
            : SMOKE_GATEWAY_CREDENTIALS_EXPLICIT;
    const librdp_status expected_gateway_status =
        gateway_profile
            ? gateway_profile->expected_status
            : LIBRDP_STATUS_OK;

    memset(&host_fixture, 0, sizeof(host_fixture));
    memset(&events, 0, sizeof(events));
    memset(&nla_provider, 0, sizeof(nla_provider));
    memset(&trace_capture, 0, sizeof(trace_capture));
    memset(&drive_confinement, 0, sizeof(drive_confinement));
    drive_confinement.socket_fd = -1;
    memset(&proxy, 0, sizeof(proxy));
    memset(&proxy_config, 0, sizeof(proxy_config));
    memset(&rdg_gateway, 0, sizeof(rdg_gateway));
    memset(&rdg_config, 0, sizeof(rdg_config));
    trace_capture.identity = identity;
    trace_capture.cancel_phase = cancel_phase;
    trace_capture.cancel_status = LIBRDP_STATUS_AGAIN;
    trace_capture.gateway_identity =
        gateway_mode != LIBRDP_GATEWAY_DISABLED
            ? (gateway_credentials ==
                       SMOKE_GATEWAY_CREDENTIALS_SESSION
                   ? identity
                   : &smoke_gateway_identity)
            : NULL;
    trace_capture.sensitive_canary =
        clipboard_profile ? clipboard_profile->sensitive_canary : NULL;
    events.clipboard_profile = clipboard_profile;
    memset(&runtime, 0, sizeof(runtime));
    memset(&key, 0, sizeof(key));
    memset(&mouse, 0, sizeof(mouse));
    REQUIRE(bind_address != NULL);
    REQUIRE(target != NULL);
    atomic_init(&host_fixture.port, 0u);
    host_fixture.status = LIBRDP_STATUS_AGAIN;
    if (drive_profile &&
        drive_profile->mode == SMOKE_DRIVE_DEVICE_NODE)
    {
        REQUIRE(snprintf(drive_directory,
                         sizeof(drive_directory),
                         "%s",
                         "/dev") ==
                (int)sizeof("/dev") - 1);
    }
    else
    {
        REQUIRE(smoke_make_drive(drive_directory,
                                 sizeof(drive_directory),
                                 drive_marker,
                                 sizeof(drive_marker)));
        drive_directory_owned = 1;
    }
    if (drive_profile &&
        drive_profile->mode == SMOKE_DRIVE_CONFINEMENT)
    {
        REQUIRE(smoke_drive_confinement_fixture_init(
            &drive_confinement,
            drive_directory));
    }
#if defined(RDP_HAVE_ATTR) && defined(__linux__)
    if (drive_profile &&
        drive_profile->mode == SMOKE_DRIVE_METADATA)
    {
        REQUIRE(setxattr(
                    drive_marker,
                    SMOKE_DRIVE_METADATA_XATTR,
                    smoke_drive_metadata_xattr,
                    sizeof(smoke_drive_metadata_xattr) - 1u,
                    0) == 0);
    }
#endif
    if (security != LIBRDP_SECURITY_STANDARD)
    {
        REQUIRE(test_server_make_tls_files(cert_path,
                                           sizeof(cert_path),
                                           key_path,
                                           sizeof(key_path)));
    }

    server_host_config_init(&host_config);
    host_config.server.bind_address = bind_address;
    host_config.server.width = SMOKE_CAPTURE_WIDTH;
    host_config.server.height = SMOKE_CAPTURE_HEIGHT;
    host_config.max_peers = 1u;
    host_config.dirty.frame_interval_ns = 0u;
    clipboard_provider =
        server_client_clipboard_provider_new(clipboard_profile);
    REQUIRE(clipboard_provider != NULL);
    events.clipboard_provider = clipboard_provider;
    smoke_platform_init(&platform,
                        &host_config,
                        clipboard_provider,
                        drive_profile);
    platform.drive_confinement =
        drive_profile &&
                drive_profile->mode == SMOKE_DRIVE_CONFINEMENT
            ? &drive_confinement
            : NULL;
    host_config.trace_callback = smoke_host_trace_callback;
    host_config.trace_user_data = &platform;
    if (auth_redirection)
    {
        atomic_init(&auth_redirection->open_requested, 0u);
        atomic_init(&auth_redirection->channel_opened, 0u);
        atomic_init(&auth_redirection->call_sent, 0u);
        atomic_init(&auth_redirection->response_received, 0u);
        atomic_init(&auth_redirection->cancellation_verified, 0u);
        atomic_init(&auth_redirection->failure_status,
                    (int)LIBRDP_STATUS_OK);
        host_config.channel_callback =
            smoke_auth_redirection_channel_callback;
        host_config.channel_user_data = auth_redirection;
        host_config.extension_callback =
            smoke_auth_redirection_extension_callback;
        host_config.extension_user_data = auth_redirection;
    }

    settings = librdp_settings_new();
    REQUIRE(settings != NULL);
    default_port = librdp_settings_port(settings);
    REQUIRE(librdp_settings_set_target(settings, target) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_desktop_size(settings,
                                             SMOKE_WIDTH,
                                             SMOKE_HEIGHT) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_add_drive(settings,
                                      "SMOKE",
                                      drive_directory) ==
            LIBRDP_STATUS_OK);
    if (drive_profile)
    {
        librdp_drive_policy drive_policy;

        if (drive_profile->mode == SMOKE_DRIVE_LIMITS)
        {
            librdp_limits limits;

            REQUIRE(librdp_limits_init(&limits) ==
                    LIBRDP_STATUS_OK);
            limits.file_handles = 3u;
            limits.file_io_bytes =
                (uint32_t)sizeof(smoke_drive_limit_valid_data);
            limits.pending_requests = 2u;
            REQUIRE(librdp_settings_set_limits(settings,
                                               &limits) ==
                    LIBRDP_STATUS_OK);
        }
        REQUIRE(librdp_drive_policy_init(&drive_policy) ==
                LIBRDP_STATUS_OK);
        drive_policy.read_only =
            drive_profile->mode == SMOKE_DRIVE_READ_ONLY ||
                    drive_profile->mode == SMOKE_DRIVE_DEVICE_NODE
                ? 1
                : 0;
        drive_policy.deny_dotfiles = 0;
        if (drive_profile->mode == SMOKE_DRIVE_LIMITS)
        {
            drive_policy.max_file_size = 6u;
            drive_policy.max_open_handles = 4u;
        }
        REQUIRE(librdp_settings_set_drive_policy(settings,
                                                 0u,
                                                 &drive_policy) ==
                LIBRDP_STATUS_OK);
        if (drive_profile->mode != SMOKE_DRIVE_DEVICE_NODE)
        {
            REQUIRE(snprintf(drive_created,
                             sizeof(drive_created),
                             "%s/created.bin",
                             drive_directory) > 0);
            REQUIRE(snprintf(drive_renamed,
                             sizeof(drive_renamed),
                             "%s/renamed.bin",
                             drive_directory) > 0);
        }
        if (drive_profile->mode == SMOKE_DRIVE_NOTIFY)
        {
            REQUIRE(snprintf(drive_notify_directory,
                             sizeof(drive_notify_directory),
                             "%s/nested",
                             drive_directory) > 0);
            REQUIRE(mkdir(drive_notify_directory,
                          S_IRWXU) == 0);
            REQUIRE(snprintf(drive_notify_first,
                             sizeof(drive_notify_first),
                             "%s/notify-first.txt",
                             drive_notify_directory) > 0);
            REQUIRE(snprintf(drive_notify_late,
                             sizeof(drive_notify_late),
                             "%s/notify-late.txt",
                             drive_notify_directory) > 0);
        }
        else if (drive_profile->mode == SMOKE_DRIVE_LIMITS)
        {
            REQUIRE(snprintf(drive_limit_primary,
                             sizeof(drive_limit_primary),
                             "%s/limit-a.bin",
                             drive_directory) > 0);
            REQUIRE(snprintf(drive_limit_quaternary,
                             sizeof(drive_limit_quaternary),
                             "%s/limit-d.bin",
                             drive_directory) > 0);
        }
    }
    REQUIRE(smoke_configure_security(&host_config,
                                     settings,
                                     security,
                                     cert_path,
                                     key_path,
                                     identity));
    REQUIRE(gateway_mode == LIBRDP_GATEWAY_DISABLED ||
            expected_connect_status == LIBRDP_STATUS_OK);
    if (expected_connect_status != LIBRDP_STATUS_OK)
    {
        REQUIRE(security == LIBRDP_SECURITY_NLA);
        nla_provider.status = expected_connect_status;
        nla_provider.expected_identity = identity;
        host_config.credentials_provider = smoke_nla_credentials_provider;
        host_config.credentials_provider_user_data = &nla_provider;
    }
    host_fixture.host = server_host_new(&host_config);
    REQUIRE(host_fixture.host != NULL);
    REQUIRE(pthread_create(&host_fixture.thread,
                           NULL,
                           smoke_host_main,
                           &host_fixture) == 0);
    thread_started = 1;
    REQUIRE(smoke_wait_for_port(&host_fixture.port, &port));
    REQUIRE(port != default_port);
    REQUIRE(librdp_settings_set_port(settings, port) == LIBRDP_STATUS_OK);
    if (gateway_mode != LIBRDP_GATEWAY_DISABLED)
    {
        int written = 0;

        if (gateway_mode == LIBRDP_GATEWAY_HTTP_CONNECT)
        {
            const smoke_nla_identity* proxy_identity =
                gateway_profile->reject_credentials
                    ? &smoke_gateway_reject_identity
                    : gateway_credentials ==
                              SMOKE_GATEWAY_CREDENTIALS_SESSION
                    ? identity
                    : &smoke_gateway_identity;
            const smoke_nla_identity* forbidden_identity =
                gateway_credentials ==
                        SMOKE_GATEWAY_CREDENTIALS_SESSION
                    ? &smoke_gateway_identity
                    : identity;

            proxy_config.target_host = target;
            proxy_config.target_port = port;
            proxy_config.gateway_username =
                proxy_identity->username;
            proxy_config.gateway_password =
                proxy_identity->password;
            proxy_config.gateway_domain =
                proxy_identity->domain;
            proxy_config.forbidden_username =
                forbidden_identity->username;
            proxy_config.forbidden_password =
                forbidden_identity->password;
            proxy_config.forbidden_domain =
                forbidden_identity->domain;
            proxy_config.behavior =
                gateway_profile->proxy_behavior;
            REQUIRE(test_http_proxy_start(&proxy, &proxy_config));
            proxy_started = 1;
            written = snprintf(gateway_url,
                               sizeof(gateway_url),
                               "http://127.0.0.1:%u",
                               (unsigned int)proxy.port);
        }
        else
        {
            const char* current_curl_ca_bundle =
                getenv("CURL_CA_BUNDLE");

            REQUIRE(gateway_mode == LIBRDP_GATEWAY_RDG_HTTP);
            REQUIRE(test_server_make_tls_files_for_host(
                gateway_cert_path,
                sizeof(gateway_cert_path),
                gateway_key_path,
                sizeof(gateway_key_path),
                "localhost"));
            rdg_config.target_host = target;
            rdg_config.target_port = port;
            rdg_config.certificate_path = gateway_cert_path;
            rdg_config.private_key_path = gateway_key_path;
            REQUIRE(test_rdg_gateway_start(&rdg_gateway,
                                           &rdg_config));
            rdg_started = 1;
            written = snprintf(
                gateway_url,
                sizeof(gateway_url),
                "https://localhost:%u/remoteDesktopGateway/",
                (unsigned int)rdg_gateway.port);
            if (current_curl_ca_bundle)
            {
                saved_curl_ca_bundle =
                    strdup(current_curl_ca_bundle);
                REQUIRE(saved_curl_ca_bundle != NULL);
            }
            if (gateway_profile->trust_certificate)
            {
                REQUIRE(setenv("CURL_CA_BUNDLE",
                               gateway_cert_path,
                               1) == 0);
            }
            else
                REQUIRE(unsetenv("CURL_CA_BUNDLE") == 0);
            curl_environment_changed = 1;
        }
        REQUIRE(written > 0 &&
                (size_t)written < sizeof(gateway_url));
        REQUIRE(librdp_gateway_config_init(&gateway_config) ==
                LIBRDP_STATUS_OK);
        gateway_config.mode = gateway_mode;
        gateway_config.url = gateway_url;
        if (gateway_credentials ==
            SMOKE_GATEWAY_CREDENTIALS_EXPLICIT)
        {
            gateway_config.username =
                smoke_gateway_identity.username;
            gateway_config.password =
                smoke_gateway_identity.password;
            gateway_config.domain =
                smoke_gateway_identity.domain;
        }
        gateway_config.use_session_credentials =
            gateway_credentials ==
            SMOKE_GATEWAY_CREDENTIALS_SESSION;
        gateway_config.timeout_ms =
            gateway_profile->timeout_ms;
        REQUIRE(librdp_settings_set_gateway_config(
                    settings,
                    &gateway_config) == LIBRDP_STATUS_OK);
    }
    trace_capture.target = target;
    trace_capture.port = port;

    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
    trace_capture.lifecycle[trace_capture.lifecycle_count++] =
        librdp_session_get_lifecycle(session);
    librdp_session_set_event_callback(session, smoke_client_event, &events);
    REQUIRE(librdp_trace_policy_init(&trace_policy) == LIBRDP_STATUS_OK);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.hex_bytes = 96u;
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = smoke_trace_callback;
    trace_policy.callback_user_data = &trace_capture;
    trace_policy.trace_id = "server-client-smoke";
    REQUIRE(librdp_session_set_trace_policy(session, &trace_policy) ==
            LIBRDP_STATUS_OK);
    client_runtime_init(&runtime, session);
    connect_status = client_runtime_connect(&runtime);
    if (gateway_mode != LIBRDP_GATEWAY_DISABLED &&
        connect_status !=
            (expected_gateway_status != LIBRDP_STATUS_OK
                 ? expected_gateway_status
                 : expected_connect_status))
    {
        const librdp_error* connect_error =
            librdp_session_last_error(session);
        librdp_error_info connect_error_info;
        const char* phase = "none";

        if (connect_error &&
            librdp_error_info_init(&connect_error_info) ==
                LIBRDP_STATUS_OK &&
            librdp_error_copy_info(connect_error,
                                   &connect_error_info) ==
                LIBRDP_STATUS_OK &&
            connect_error_info.phase)
            phase = connect_error_info.phase;
        fprintf(stderr,
                "gateway smoke mode=%u connect=%s phase=%s http_proxy=%s rdg=%s authenticated=%u forwarded=%u leak=%u\n",
                (unsigned int)gateway_mode,
                librdp_status_name(connect_status),
                phase,
                librdp_status_name(proxy.status),
                librdp_status_name(rdg_gateway.status),
                atomic_load_explicit(&proxy.authenticated,
                                     memory_order_acquire),
                atomic_load_explicit(&proxy.forwarded,
                                     memory_order_acquire),
                atomic_load_explicit(&proxy.credential_leak,
                                     memory_order_acquire));
    }
    if (expected_gateway_status != LIBRDP_STATUS_OK)
    {
        const librdp_error* error = NULL;

        REQUIRE(connect_status == expected_gateway_status);
        REQUIRE(nla_provider.calls == 0u);
        REQUIRE(trace_capture.records > 0u);
        REQUIRE(trace_capture.connect_starts == 0u);
        REQUIRE(trace_capture.connect_completions == 0u);
        REQUIRE(trace_capture.leaked == 0);
        if (gateway_mode == LIBRDP_GATEWAY_HTTP_CONNECT)
        {
            REQUIRE(trace_capture.gateway_connect_starts ==
                    1u);
            REQUIRE(trace_capture.gateway_connect_completions ==
                    0u);
            REQUIRE(atomic_load_explicit(
                        &proxy.requests,
                        memory_order_acquire) > 0u);
            REQUIRE(atomic_load_explicit(
                        &proxy.authenticated,
                        memory_order_acquire) == 0u);
            REQUIRE(atomic_load_explicit(
                        &proxy.forwarded,
                        memory_order_acquire) == 0u);
            REQUIRE(atomic_load_explicit(
                        &proxy.credential_leak,
                        memory_order_acquire) == 0u);
        }
        else
        {
            REQUIRE(gateway_mode == LIBRDP_GATEWAY_RDG_HTTP);
            REQUIRE(trace_capture.gateway_connect_starts ==
                    0u);
            REQUIRE(trace_capture.gateway_connect_completions ==
                    0u);
            REQUIRE(trace_capture.rdg_connect_starts == 1u);
            REQUIRE(trace_capture.rdg_connect_completions ==
                    0u);
        }
        error = librdp_session_last_error(session);
        REQUIRE(error != NULL);
        REQUIRE(librdp_error_info_init(&error_info) ==
                LIBRDP_STATUS_OK);
        REQUIRE(librdp_error_copy_info(error, &error_info) ==
                LIBRDP_STATUS_OK);
        REQUIRE(error_info.status == expected_gateway_status);
        REQUIRE(error_info.component ==
                LIBRDP_ERROR_COMPONENT_TRANSPORT);
        REQUIRE(error_info.phase != NULL);
        REQUIRE(strcmp(error_info.phase,
                       "transport.gateway.connect") == 0);
        REQUIRE(error_info.trace_id != NULL);
        REQUIRE(strcmp(error_info.trace_id,
                       "server-client-smoke") == 0);
        if (proxy_started)
        {
            test_http_proxy_cancel(&proxy);
            REQUIRE(test_http_proxy_join_status(
                &proxy,
                gateway_profile->expected_fixture_status));
            proxy_started = 0;
            test_http_proxy_clear(&proxy);
        }
        if (rdg_started)
        {
            test_rdg_gateway_cancel(&rdg_gateway);
            REQUIRE(test_rdg_gateway_join_status(
                &rdg_gateway,
                gateway_profile->expected_fixture_status));
            rdg_started = 0;
            test_rdg_gateway_clear(&rdg_gateway);
        }
        REQUIRE(server_host_cancel(host_fixture.host) ==
                LIBRDP_STATUS_OK);
        REQUIRE(pthread_join(host_fixture.thread, NULL) == 0);
        thread_started = 0;
        REQUIRE(host_fixture.status == LIBRDP_STATUS_OK);
        result = 0;
        goto cleanup;
    }
    if (cancel_phase >= 0)
    {
        terminal_status = connect_status;
        if (terminal_status == LIBRDP_STATUS_OK)
        {
            for (cycle = 0u;
                 cycle < 4u &&
                 terminal_status == LIBRDP_STATUS_OK;
                 cycle++)
            {
                terminal_status = smoke_client_pump(&runtime);
            }
        }
        REQUIRE(terminal_status == LIBRDP_STATUS_CANCELLED);
        REQUIRE(trace_capture.cancel_requests == 1u);
        REQUIRE(trace_capture.cancel_status == LIBRDP_STATUS_OK);
        REQUIRE(trace_capture.client_connect_successes == 0u);
        REQUIRE(trace_capture.client_connect_failures == 0u);
        REQUIRE(trace_capture.client_connect_cancellations == 1u);
        REQUIRE(trace_capture.credssp_failures == 0u);
        REQUIRE(trace_capture.tls_connect_failures == 0u);
        REQUIRE(librdp_session_get_state(session) ==
                LIBRDP_SESSION_CANCELLED);
        REQUIRE(librdp_session_get_lifecycle(session) ==
                LIBRDP_LIFECYCLE_DISCONNECTED);
        REQUIRE(!events.active);
        REQUIRE(events.error_events == 0u);
        REQUIRE(trace_capture.leaked == 0);
        REQUIRE(librdp_error_info_init(&error_info) ==
                LIBRDP_STATUS_OK);
        REQUIRE(librdp_error_copy_info(
                    librdp_session_last_error(session),
                    &error_info) == LIBRDP_STATUS_OK);
        REQUIRE(error_info.status == LIBRDP_STATUS_CANCELLED);
        REQUIRE(error_info.component ==
                LIBRDP_ERROR_COMPONENT_CLIENT);
        REQUIRE(error_info.phase != NULL);
        REQUIRE(strcmp(error_info.phase, "client.cancel") == 0);
        REQUIRE(error_info.trace_id != NULL);
        REQUIRE(strcmp(error_info.trace_id,
                       "server-client-smoke") == 0);
        REQUIRE(server_host_cancel(host_fixture.host) ==
                LIBRDP_STATUS_OK);
        REQUIRE(pthread_join(host_fixture.thread, NULL) == 0);
        thread_started = 0;
        REQUIRE(host_fixture.status == LIBRDP_STATUS_OK);
        result = 0;
        goto cleanup;
    }
    if (expected_connect_status != LIBRDP_STATUS_OK)
    {
        const librdp_error* error = NULL;

        REQUIRE(connect_status == expected_connect_status);
        REQUIRE(nla_provider.calls == 1u);
        REQUIRE(nla_provider.identity_matched);
        REQUIRE(trace_capture.records > 0u);
        REQUIRE(trace_capture.connect_starts == 1u);
        REQUIRE(trace_capture.connect_completions == 1u);
        REQUIRE(trace_capture.address_matched);
        REQUIRE(trace_capture.leaked == 0);
        error = librdp_session_last_error(session);
        REQUIRE(error != NULL);
        REQUIRE(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
        REQUIRE(librdp_error_copy_info(error, &error_info) ==
                LIBRDP_STATUS_OK);
        REQUIRE(error_info.status == expected_connect_status);
        REQUIRE(error_info.os_errno == 0);
        REQUIRE(error_info.component == LIBRDP_ERROR_COMPONENT_CREDSSP);
        REQUIRE(error_info.phase != NULL);
        REQUIRE(strcmp(error_info.phase, "credssp.nla.authenticate") == 0);
        REQUIRE(error_info.trace_id != NULL);
        REQUIRE(strcmp(error_info.trace_id,
                       "server-client-smoke") == 0);
        (void)server_host_cancel(host_fixture.host);
        REQUIRE(pthread_join(host_fixture.thread, NULL) == 0);
        thread_started = 0;
        REQUIRE(host_fixture.status == LIBRDP_STATUS_OK);
        result = 0;
        goto cleanup;
    }
    REQUIRE(connect_status == LIBRDP_STATUS_OK);
    for (cycle = 0u; cycle < SMOKE_PUMP_LIMIT; cycle++)
    {
        const librdp_surface* surface = NULL;
        int desktop_ready = 0;
        int frame_complete = 0;
        librdp_status status = smoke_client_pump(&runtime);

        if (status != LIBRDP_STATUS_OK)
        {
            librdp_error_info pump_error_info;
            const librdp_error* pump_error =
                librdp_session_last_error(session);
            const char* pump_phase = "none";
            librdp_status pump_error_status =
                LIBRDP_STATUS_OK;
            size_t trace_index = 0u;

            if (pump_error &&
                librdp_error_info_init(&pump_error_info) ==
                    LIBRDP_STATUS_OK &&
                librdp_error_copy_info(pump_error,
                                       &pump_error_info) ==
                    LIBRDP_STATUS_OK)
            {
                pump_error_status = pump_error_info.status;
                if (pump_error_info.phase)
                    pump_phase = pump_error_info.phase;
            }
            fprintf(stderr,
                    "client pump failed status=%s error=%s phase=%s host=%s rdg=%s out=%u in=%u channel=%u sent=%u received=%u\n",
                    librdp_status_name(status),
                    librdp_status_name(pump_error_status),
                    pump_phase,
                    librdp_status_name(host_fixture.status),
                    librdp_status_name(rdg_gateway.status),
                    atomic_load_explicit(&rdg_gateway.out_stream,
                                         memory_order_acquire),
                    atomic_load_explicit(&rdg_gateway.in_stream,
                                         memory_order_acquire),
                    atomic_load_explicit(&rdg_gateway.channel,
                                         memory_order_acquire),
                    atomic_load_explicit(
                        &rdg_gateway.downstream_sent,
                        memory_order_acquire),
                    atomic_load_explicit(
                        &rdg_gateway.downstream_received,
                        memory_order_acquire));
            for (trace_index = 0u;
                 trace_index < trace_capture.recent_count;
                 trace_index++)
            {
                size_t slot =
                    (trace_capture.recent_next +
                     SMOKE_TRACE_RECENT_CAPACITY -
                     trace_capture.recent_count +
                     trace_index) %
                    SMOKE_TRACE_RECENT_CAPACITY;

                fprintf(stderr,
                        "recent trace: %s\n",
                        trace_capture.recent[slot]);
            }
        }
        REQUIRE(status == LIBRDP_STATUS_OK);
        surface = librdp_session_get_surface(session);
        desktop_ready =
            events.active && surface &&
            librdp_surface_width(surface) == SMOKE_WIDTH &&
            librdp_surface_height(surface) == SMOKE_HEIGHT;
        if (desktop_ready && !clipboard_sent)
        {
            if (clipboard_profile)
                status =
                    server_client_clipboard_provider_publish_client(
                        clipboard_provider,
                        session);
            else
            {
                status = librdp_session_clipboard_set_data(
                    session,
                    LIBRDP_CLIPBOARD_FORMAT_TEXT,
                    clipboard_data,
                    sizeof(clipboard_data));
            }
            if (status == LIBRDP_STATUS_OK)
                clipboard_sent = 1;
            else
                REQUIRE(status == LIBRDP_STATUS_STATE);
        }
        if (desktop_ready && !input_sent)
        {
            key.scancode = 0x1eu;
            key.state = LIBRDP_KEY_PRESSED;
            REQUIRE(librdp_session_send_key(session, &key) ==
                    LIBRDP_STATUS_OK);
            key.state = LIBRDP_KEY_RELEASED;
            REQUIRE(librdp_session_send_key(session, &key) ==
                    LIBRDP_STATUS_OK);
            memset(&key, 0, sizeof(key));
            key.flags = LIBRDP_KEY_FLAG_UNICODE;
            key.unicode = 0x00e9u;
            key.state = LIBRDP_KEY_PRESSED;
            REQUIRE(librdp_session_send_key(session, &key) ==
                    LIBRDP_STATUS_OK);
            key.state = LIBRDP_KEY_RELEASED;
            REQUIRE(librdp_session_send_key(session, &key) ==
                    LIBRDP_STATUS_OK);
            mouse.x = 7u;
            mouse.y = 9u;
            mouse.button = LIBRDP_MOUSE_BUTTON_NONE;
            mouse.state = LIBRDP_MOUSE_MOVED;
            REQUIRE(librdp_session_send_mouse(session, &mouse) ==
                    LIBRDP_STATUS_OK);
            mouse.x = 11u;
            mouse.y = 13u;
            mouse.button = LIBRDP_MOUSE_BUTTON_X1;
            mouse.state = LIBRDP_MOUSE_PRESSED;
            REQUIRE(librdp_session_send_mouse(session, &mouse) ==
                    LIBRDP_STATUS_OK);
            mouse.state = LIBRDP_MOUSE_RELEASED;
            REQUIRE(librdp_session_send_mouse(session, &mouse) ==
                    LIBRDP_STATUS_OK);
            input_sent = 1;
        }
        if (exercise_output_control &&
            output_control_stage == 0 &&
            desktop_ready && events.surface_events > 0u &&
            clipboard_sent && input_sent &&
            server_client_clipboard_provider_has_offer(
                clipboard_provider) &&
            atomic_load_explicit(&platform.drive_presentations,
                                 memory_order_acquire) > 0u)
        {
            const uint8_t* pixels =
                librdp_surface_pixels(surface);

            REQUIRE(pixels != NULL);
            memcpy(initial_pixel, pixels, sizeof(initial_pixel));
            refresh_requests_before =
                atomic_load_explicit(&platform.refresh_requests,
                                     memory_order_acquire);
            output_suppressions_before =
                atomic_load_explicit(
                    &platform.output_suppressions,
                    memory_order_acquire);
            output_resumptions_before =
                atomic_load_explicit(
                    &platform.output_resumptions,
                    memory_order_acquire);
            capture_before_refresh =
                atomic_load_explicit(&platform.capture_requests,
                                     memory_order_acquire);
            atomic_store_explicit(&platform.capture_variant,
                                  1u,
                                  memory_order_release);
            REQUIRE(librdp_session_set_output_suppressed(
                        session,
                        1) == LIBRDP_STATUS_OK);
            REQUIRE(librdp_session_refresh(session,
                                           1u,
                                           2u,
                                           7u,
                                           5u) ==
                    LIBRDP_STATUS_OK);
            output_control_stage = 1;
        }
        else if (exercise_output_control &&
                 output_control_stage == 1 &&
                 atomic_load_explicit(
                     &platform.output_suppressions,
                     memory_order_acquire) >
                     output_suppressions_before &&
                 atomic_load_explicit(
                     &platform.refresh_requests,
                     memory_order_acquire) >
                     refresh_requests_before &&
                 atomic_load_explicit(
                     &platform.capture_requests,
                     memory_order_acquire) >
                     capture_before_refresh)
        {
            const uint8_t* pixels =
                librdp_surface_pixels(surface);

            REQUIRE(pixels != NULL);
            REQUIRE(memcmp(pixels,
                           initial_pixel,
                           sizeof(initial_pixel)) == 0);
            surface_events_before_resume = events.surface_events;
            REQUIRE(librdp_session_set_output_suppressed(
                        session,
                        0) == LIBRDP_STATUS_OK);
            output_control_stage = 2;
        }
        else if (exercise_output_control &&
                 output_control_stage == 2 &&
                 atomic_load_explicit(
                     &platform.output_resumptions,
                     memory_order_acquire) >
                     output_resumptions_before)
        {
            const uint8_t* pixels =
                librdp_surface_pixels(surface);

            if (pixels &&
                smoke_frame_matches_sha256(
                    pixels,
                    (size_t)librdp_surface_stride(surface) *
                        librdp_surface_height(surface),
                    smoke_alternate_frame_sha256) &&
                events.surface_events >
                    surface_events_before_resume)
            {
                output_control_stage = 3;
            }
        }
        if (drive_profile &&
            drive_profile->mode == SMOKE_DRIVE_NOTIFY)
        {
            unsigned int drive_stage =
                atomic_load_explicit(&platform.drive_stage,
                                     memory_order_acquire);

            if (drive_stage ==
                    SMOKE_DRIVE_STAGE_NOTIFY_FIRST_PENDING &&
                trace_capture.directory_notify_requests >= 1u)
            {
                unsigned int expected =
                    SMOKE_DRIVE_STAGE_NOTIFY_FIRST_PENDING;

                if (atomic_compare_exchange_strong_explicit(
                        &platform.drive_stage,
                        &expected,
                        SMOKE_DRIVE_STAGE_NOTIFY_FIRST_WAIT_COMPLETION,
                        memory_order_acq_rel,
                        memory_order_acquire))
                    REQUIRE(smoke_write_drive_file(
                        drive_notify_first));
            }
            else if (drive_stage ==
                         SMOKE_DRIVE_STAGE_NOTIFY_LATE_PENDING &&
                     trace_capture.directory_notify_requests >= 2u)
            {
                unsigned int expected =
                    SMOKE_DRIVE_STAGE_NOTIFY_LATE_PENDING;

                if (atomic_compare_exchange_strong_explicit(
                        &platform.drive_stage,
                        &expected,
                        SMOKE_DRIVE_STAGE_NOTIFY_LATE_DRAIN,
                        memory_order_acq_rel,
                        memory_order_acquire))
                {
                    atomic_store_explicit(
                        &platform.drive_wait_cycles,
                        0u,
                        memory_order_release);
                    REQUIRE(smoke_write_drive_file(
                        drive_notify_late));
                }
            }
            else if (drive_stage ==
                     SMOKE_DRIVE_STAGE_NOTIFY_LATE_DRAIN)
            {
                if (trace_capture.directory_notify_completions < 2u)
                {
                    atomic_store_explicit(
                        &platform.drive_wait_cycles,
                        0u,
                        memory_order_release);
                }
                else if (atomic_fetch_add_explicit(
                             &platform.drive_wait_cycles,
                             1u,
                             memory_order_acq_rel) >= 4u)
                {
                    unsigned int expected =
                        SMOKE_DRIVE_STAGE_NOTIFY_LATE_DRAIN;

                    (void)atomic_compare_exchange_strong_explicit(
                        &platform.drive_stage,
                        &expected,
                        SMOKE_DRIVE_STAGE_NOTIFY_RECONNECT_READY,
                        memory_order_acq_rel,
                        memory_order_acquire);
                }
            }
            else if (drive_stage ==
                     SMOKE_DRIVE_STAGE_NOTIFY_RECONNECT_READY)
            {
                unsigned int expected =
                    SMOKE_DRIVE_STAGE_NOTIFY_RECONNECT_READY;

                if (atomic_compare_exchange_strong_explicit(
                        &platform.drive_stage,
                        &expected,
                        SMOKE_DRIVE_STAGE_NOTIFY_RECONNECTING,
                        memory_order_acq_rel,
                        memory_order_acquire))
                {
                    REQUIRE(librdp_session_reconnect(
                                session,
                                NULL) == LIBRDP_STATUS_OK);
                }
            }
        }
        else if (drive_profile &&
                 drive_profile->mode == SMOKE_DRIVE_LIMITS)
        {
            unsigned int drive_stage =
                atomic_load_explicit(&platform.drive_stage,
                                     memory_order_acquire);

            if (drive_stage ==
                    SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_FIRST_PENDING &&
                trace_capture.directory_notify_requests >= 1u)
            {
                unsigned int expected =
                    SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_FIRST_PENDING;

                if (atomic_compare_exchange_strong_explicit(
                        &platform.drive_stage,
                        &expected,
                        SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_SUBMIT_SECOND,
                        memory_order_acq_rel,
                        memory_order_acquire))
                {
                    smoke_drive_submit_notify(
                        &platform,
                        SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_SECOND_PENDING,
                        platform.drive_secondary_file,
                        RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_FILE_NAME);
                    platform.drive_pending_request_ids[1] =
                        platform.drive_next_request_id;
                }
            }
            else if (drive_stage ==
                         SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_SECOND_PENDING &&
                     trace_capture.directory_notify_requests >= 2u)
            {
                unsigned int expected =
                    SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_SECOND_PENDING;

                if (atomic_compare_exchange_strong_explicit(
                        &platform.drive_stage,
                        &expected,
                        SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_SUBMIT_THIRD,
                        memory_order_acq_rel,
                        memory_order_acquire))
                {
                    smoke_drive_submit_notify(
                        &platform,
                        SMOKE_DRIVE_STAGE_REJECT_LIMIT_NOTIFY_THIRD,
                        platform.drive_directory,
                        RDP_FILESYSTEM_REDIRECTION_NOTIFY_CHANGE_FILE_NAME);
                }
            }
            else if (drive_stage ==
                     SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_WAIT_CANCEL_FIRST)
            {
                unsigned int expected =
                    SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_WAIT_CANCEL_FIRST;

                if (atomic_compare_exchange_strong_explicit(
                        &platform.drive_stage,
                        &expected,
                        SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_CANCEL_FIRST_PENDING,
                        memory_order_acq_rel,
                        memory_order_acquire))
                {
                    REQUIRE(platform.drive_sink.cancel != NULL);
                    platform.drive_sink.cancel(
                        platform.drive_volume.peer_id,
                        platform.drive_volume.generation,
                        platform.drive_pending_request_ids[0],
                        platform.drive_sink.user_data);
                }
            }
            else if (drive_stage ==
                     SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_WAIT_CANCEL_SECOND)
            {
                unsigned int expected =
                    SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_WAIT_CANCEL_SECOND;

                if (atomic_compare_exchange_strong_explicit(
                        &platform.drive_stage,
                        &expected,
                        SMOKE_DRIVE_STAGE_LIMIT_NOTIFY_CANCEL_SECOND_PENDING,
                        memory_order_acq_rel,
                        memory_order_acquire))
                {
                    REQUIRE(platform.drive_sink.cancel != NULL);
                    platform.drive_sink.cancel(
                        platform.drive_volume.peer_id,
                        platform.drive_volume.generation,
                        platform.drive_pending_request_ids[1],
                        platform.drive_sink.user_data);
                }
            }
        }
        if (desktop_ready)
        {
            const uint8_t* pixels = librdp_surface_pixels(surface);

            frame_complete = pixels &&
                smoke_frame_matches_sha256(
                    pixels,
                    (size_t)librdp_surface_stride(surface) *
                        librdp_surface_height(surface),
                    exercise_output_control ?
                        smoke_alternate_frame_sha256 :
                        smoke_frame_sha256);
        }
        if (desktop_ready && frame_complete && events.surface_events > 0u &&
            trace_capture.slowpath_bitmap_updates > 0u &&
            clipboard_sent &&
            server_client_clipboard_provider_has_offer(
                clipboard_provider) &&
            atomic_load_explicit(&platform.drive_presentations,
                                 memory_order_acquire) > 0u &&
            atomic_load_explicit(&platform.key_events,
                                 memory_order_acquire) >= 2u &&
            atomic_load_explicit(&platform.unicode_events,
                                 memory_order_acquire) >= 2u &&
            atomic_load_explicit(&platform.mouse_events,
                                 memory_order_acquire) >= 1u &&
            atomic_load_explicit(&platform.extended_mouse_events,
                                 memory_order_acquire) >= 2u &&
            atomic_load_explicit(&platform.input_validation_errors,
                                 memory_order_acquire) == 0u &&
            (!clipboard_profile ||
             smoke_clipboard_profile_complete(clipboard_provider,
                                              &events)) &&
            (!drive_profile ||
             atomic_load_explicit(&platform.drive_stage,
                                  memory_order_acquire) ==
                 SMOKE_DRIVE_STAGE_COMPLETE) &&
            (!exercise_output_control ||
             output_control_stage == 3))
            break;
        if (drive_profile &&
            atomic_load_explicit(&platform.drive_stage,
                                 memory_order_acquire) ==
                SMOKE_DRIVE_STAGE_FAILED)
            break;
        if (drive_profile)
        {
            smoke_drive_stage drive_stage =
                (smoke_drive_stage)atomic_load_explicit(
                    &platform.drive_stage,
                    memory_order_acquire);

            if (drive_stage != SMOKE_DRIVE_STAGE_COMPLETE &&
                drive_stage != SMOKE_DRIVE_STAGE_FAILED)
            {
                const struct timespec delay = {0, 1000000L};

                (void)nanosleep(&delay, NULL);
            }
        }
    }
    if (cycle >= SMOKE_PUMP_LIMIT && exercise_output_control)
    {
        fprintf(stderr,
                "output control timeout stage=%d capture=%u refresh=%u suppress=%u resume=%u surface=%u clipboard=%u drive=%u keys=%u mouse=%u\n",
                output_control_stage,
                atomic_load_explicit(&platform.capture_requests,
                                     memory_order_acquire),
                atomic_load_explicit(&platform.refresh_requests,
                                     memory_order_acquire),
                atomic_load_explicit(&platform.output_suppressions,
                                     memory_order_acquire),
                atomic_load_explicit(&platform.output_resumptions,
                                     memory_order_acquire),
                events.surface_events,
                (unsigned int)
                    server_client_clipboard_provider_has_offer(
                        clipboard_provider),
                atomic_load_explicit(&platform.drive_presentations,
                                     memory_order_acquire),
                atomic_load_explicit(&platform.key_events,
                                     memory_order_acquire),
                atomic_load_explicit(&platform.mouse_events,
                                     memory_order_acquire));
    }
    REQUIRE(cycle < SMOKE_PUMP_LIMIT);
    REQUIRE(events.active);
    if (auth_redirection)
    {
        for (cycle = 0u;
             cycle < SMOKE_PUMP_LIMIT &&
             atomic_load_explicit(
                 &auth_redirection->cancellation_verified,
                 memory_order_acquire) == 0u &&
             atomic_load_explicit(&auth_redirection->failure_status,
                                  memory_order_acquire) ==
                 (int)LIBRDP_STATUS_OK;
             cycle++)
        {
            terminal_status = smoke_client_pump(&runtime);
            REQUIRE(terminal_status == LIBRDP_STATUS_OK);
        }
        REQUIRE(cycle < SMOKE_PUMP_LIMIT);
        REQUIRE(atomic_load_explicit(&auth_redirection->open_requested,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(&auth_redirection->channel_opened,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(&auth_redirection->call_sent,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(&auth_redirection->response_received,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(
                    &auth_redirection->cancellation_verified,
                    memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(&auth_redirection->failure_status,
                                     memory_order_acquire) ==
                (int)LIBRDP_STATUS_OK);
        for (cycle = 0u; cycle < 16u; cycle++)
        {
            terminal_status = smoke_client_pump(&runtime);
            REQUIRE(terminal_status == LIBRDP_STATUS_OK);
        }
    }
    REQUIRE(events.surface_events > 0u);
    REQUIRE(events.error_events == 0u);
    REQUIRE(trace_capture.records > 0u);
    if (gateway_mode == LIBRDP_GATEWAY_HTTP_CONNECT)
    {
        REQUIRE(trace_capture.connect_starts == 0u);
        REQUIRE(trace_capture.connect_completions == 0u);
        REQUIRE(trace_capture.gateway_connect_starts == 1u);
        REQUIRE(trace_capture.gateway_connect_completions == 1u);
        REQUIRE(atomic_load_explicit(&proxy.authenticated,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(&proxy.forwarded,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(&proxy.credential_leak,
                                     memory_order_acquire) == 0u);
    }
    else if (gateway_mode == LIBRDP_GATEWAY_RDG_HTTP)
    {
        REQUIRE(trace_capture.connect_starts == 0u);
        REQUIRE(trace_capture.connect_completions == 0u);
        REQUIRE(trace_capture.gateway_connect_starts == 0u);
        REQUIRE(trace_capture.gateway_connect_completions == 0u);
        REQUIRE(trace_capture.rdg_connect_starts == 1u);
        REQUIRE(trace_capture.rdg_connect_completions == 1u);
        REQUIRE(trace_capture.rdg_handshakes == 1u);
        REQUIRE(trace_capture.rdg_tunnels == 1u);
        REQUIRE(trace_capture.rdg_authentications == 1u);
        REQUIRE(trace_capture.rdg_channels == 1u);
        REQUIRE(atomic_load_explicit(&rdg_gateway.out_stream,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(&rdg_gateway.in_stream,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(&rdg_gateway.handshake,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(&rdg_gateway.tunnel,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(&rdg_gateway.authorized,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(&rdg_gateway.channel,
                                     memory_order_acquire) == 1u);
        REQUIRE(atomic_load_explicit(
                    &rdg_gateway.downstream_sent,
                    memory_order_acquire) > 0u);
        REQUIRE(atomic_load_explicit(
                    &rdg_gateway.downstream_received,
                    memory_order_acquire) > 0u);
    }
    else
    {
        unsigned int expected_connections =
            drive_profile &&
                    drive_profile->mode == SMOKE_DRIVE_NOTIFY
                ? 2u
                : 1u;

        REQUIRE(trace_capture.connect_starts ==
                expected_connections);
        REQUIRE(trace_capture.connect_completions ==
                expected_connections);
        REQUIRE(trace_capture.address_matched);
    }
    REQUIRE(trace_capture.leaked == 0);
    REQUIRE(librdp_surface_width(librdp_session_get_surface(session)) ==
            SMOKE_WIDTH);
    REQUIRE(librdp_surface_height(librdp_session_get_surface(session)) ==
            SMOKE_HEIGHT);
    REQUIRE(librdp_surface_stride(librdp_session_get_surface(session)) ==
            SMOKE_WIDTH * 4u);
    REQUIRE(trace_capture.slowpath_bitmap_updates > 0u);
    REQUIRE(smoke_frame_matches_sha256(
        librdp_surface_pixels(librdp_session_get_surface(session)),
        (size_t)librdp_surface_stride(
            librdp_session_get_surface(session)) *
            librdp_surface_height(
                librdp_session_get_surface(session)),
        exercise_output_control
            ? smoke_alternate_frame_sha256
            : smoke_frame_sha256));
    REQUIRE(clipboard_sent);
    REQUIRE(input_sent);
    REQUIRE(atomic_load_explicit(&platform.capture_requests,
                                 memory_order_acquire) > 0u);
    REQUIRE(server_client_clipboard_provider_has_offer(
        clipboard_provider));
    REQUIRE(atomic_load_explicit(&platform.drive_presentations,
                                 memory_order_acquire) > 0u);
    if (drive_profile)
    {
        smoke_drive_stage drive_stage =
            (smoke_drive_stage)atomic_load_explicit(
                &platform.drive_stage,
                memory_order_acquire);

        if (drive_stage != SMOKE_DRIVE_STAGE_COMPLETE)
        {
            fprintf(stderr,
                    "drive smoke incomplete stage=%u completions=%u status=%s io_status=%u\n",
                    (unsigned int)drive_stage,
                    atomic_load_explicit(&platform.drive_completions,
                                         memory_order_acquire),
                    librdp_status_name(platform.drive_failure_status),
                    platform.drive_failure_io_status);
        }
        REQUIRE(drive_stage == SMOKE_DRIVE_STAGE_COMPLETE);
        REQUIRE(platform.drive_failure_status == LIBRDP_STATUS_OK);
        REQUIRE(platform.drive_failure_io_status == 0u);
        if (drive_profile->mode == SMOKE_DRIVE_READ_ONLY)
        {
            REQUIRE(atomic_load_explicit(&platform.drive_completions,
                                         memory_order_acquire) == 10u);
            REQUIRE(access(drive_marker, F_OK) == 0);
            REQUIRE(access(drive_renamed, F_OK) != 0);
        }
        else if (drive_profile->mode == SMOKE_DRIVE_WRITABLE)
        {
            REQUIRE(atomic_load_explicit(&platform.drive_completions,
                                         memory_order_acquire) == 10u);
            REQUIRE(access(drive_created, F_OK) != 0);
            REQUIRE(access(drive_renamed, F_OK) != 0);
        }
        else if (drive_profile->mode ==
                 SMOKE_DRIVE_INFORMATION)
        {
            REQUIRE(atomic_load_explicit(&platform.drive_completions,
                                         memory_order_acquire) == 52u);
            REQUIRE(access(drive_marker, F_OK) == 0);
            REQUIRE(access(drive_created, F_OK) != 0);
            REQUIRE(access(drive_renamed, F_OK) != 0);
        }
        else if (drive_profile->mode ==
                 SMOKE_DRIVE_ENUMERATION)
        {
            REQUIRE(atomic_load_explicit(&platform.drive_completions,
                                         memory_order_acquire) == 7u);
            REQUIRE(access(drive_marker, F_OK) == 0);
        }
        else if (drive_profile->mode == SMOKE_DRIVE_NOTIFY)
        {
            REQUIRE(atomic_load_explicit(
                        &platform.drive_completions,
                        memory_order_acquire) == 7u);
            REQUIRE(atomic_load_explicit(
                        &platform.drive_presentations,
                        memory_order_acquire) == 2u);
            REQUIRE(atomic_load_explicit(
                        &platform.drive_removals,
                        memory_order_acquire) >= 1u);
            REQUIRE(platform.drive_previous_generation !=
                    platform.drive_volume.generation);
            REQUIRE(trace_capture.directory_notify_requests == 3u);
            REQUIRE(trace_capture.directory_notify_completions == 2u);
            REQUIRE(access(drive_notify_first, F_OK) == 0);
            REQUIRE(access(drive_notify_late, F_OK) == 0);
        }
        else if (drive_profile->mode == SMOKE_DRIVE_METADATA)
        {
#if defined(RDP_HAVE_ATTR) && defined(__linux__)
            struct stat metadata_st;
            uint8_t xattr_value[64];
            ssize_t xattr_len = 0;

            memset(&metadata_st, 0, sizeof(metadata_st));
            memset(xattr_value, 0, sizeof(xattr_value));
            REQUIRE(atomic_load_explicit(
                        &platform.drive_completions,
                        memory_order_acquire) == 11u);
            REQUIRE(stat(drive_marker, &metadata_st) == 0);
            REQUIRE(metadata_st.st_size ==
                    (off_t)(SMOKE_DRIVE_LARGE_OFFSET + 1u));
            REQUIRE((metadata_st.st_mode & 0777u) ==
                    SMOKE_DRIVE_METADATA_MODE);
            REQUIRE(metadata_st.st_blocks >= 0);
            REQUIRE((uint64_t)metadata_st.st_blocks * 512u <
                    SMOKE_DRIVE_LARGE_OFFSET);
            xattr_len = getxattr(drive_marker,
                                 SMOKE_DRIVE_METADATA_XATTR,
                                 xattr_value,
                                 sizeof(xattr_value));
            REQUIRE(xattr_len ==
                    (ssize_t)(sizeof(smoke_drive_metadata_xattr) -
                              1u));
            REQUIRE(memcmp(xattr_value,
                           smoke_drive_metadata_xattr,
                           sizeof(smoke_drive_metadata_xattr) -
                               1u) == 0);
            memset(xattr_value, 0, sizeof(xattr_value));
            xattr_len = getxattr(
                drive_marker,
                SMOKE_DRIVE_DOS_ATTRIBUTES_XATTR,
                xattr_value,
                sizeof(xattr_value));
            REQUIRE(xattr_len ==
                    (ssize_t)(sizeof("0x00000020") - 1u));
            REQUIRE(memcmp(xattr_value,
                           "0x00000020",
                           sizeof("0x00000020") - 1u) == 0);
#else
            REQUIRE(0);
#endif
        }
        else if (drive_profile->mode ==
                 SMOKE_DRIVE_CONFINEMENT)
        {
            REQUIRE(atomic_load_explicit(
                        &platform.drive_completions,
                        memory_order_acquire) == 10u);
            REQUIRE(smoke_drive_confinement_fixture_valid(
                &drive_confinement));
            REQUIRE(access(drive_marker, F_OK) == 0);
        }
        else if (drive_profile->mode ==
                 SMOKE_DRIVE_DEVICE_NODE)
        {
            REQUIRE(atomic_load_explicit(
                        &platform.drive_completions,
                        memory_order_acquire) == 1u);
            REQUIRE(access("/dev/null", F_OK) == 0);
        }
        else if (drive_profile->mode ==
                 SMOKE_DRIVE_LIMITS)
        {
            librdp_metrics metrics;

            REQUIRE(atomic_load_explicit(
                        &platform.drive_completions,
                        memory_order_acquire) == 21u);
            REQUIRE(trace_capture.directory_notify_requests == 3u);
            REQUIRE(trace_capture.directory_notify_completions == 0u);
            REQUIRE(smoke_drive_limit_file_valid(
                drive_limit_primary));
            REQUIRE(access(drive_limit_quaternary, F_OK) != 0);
            REQUIRE(librdp_metrics_init(&metrics) ==
                    LIBRDP_STATUS_OK);
            REQUIRE(librdp_session_get_metrics(session,
                                               &metrics) ==
                    LIBRDP_STATUS_OK);
            REQUIRE(metrics.limits_rejected == 4u);
        }
        else
        {
            REQUIRE(drive_profile->mode ==
                    SMOKE_DRIVE_LOCKING);
            REQUIRE(atomic_load_explicit(&platform.drive_completions,
                                         memory_order_acquire) == 12u);
            REQUIRE(access(drive_marker, F_OK) == 0);
        }
    }
    REQUIRE(atomic_load_explicit(&platform.key_events,
                                 memory_order_acquire) >= 2u);
    REQUIRE(atomic_load_explicit(&platform.unicode_events,
                                 memory_order_acquire) >= 2u);
    REQUIRE(atomic_load_explicit(&platform.mouse_events,
                                 memory_order_acquire) >= 1u);
    REQUIRE(atomic_load_explicit(&platform.extended_mouse_events,
                                 memory_order_acquire) >= 2u);
    REQUIRE(atomic_load_explicit(&platform.input_validation_errors,
                                 memory_order_acquire) == 0u);
    if (clipboard_profile)
    {
        REQUIRE(smoke_clipboard_profile_complete(clipboard_provider,
                                                 &events));
        REQUIRE(trace_capture.clipboard_format_lists >= 1u);
        REQUIRE(trace_capture.clipboard_requests == 1u);
        REQUIRE(trace_capture.clipboard_responses == 1u);
        REQUIRE(trace_capture.clipboard_local_responses == 1u);
        if (server_client_clipboard_profile_is_file_transfer(
                clipboard_profile))
        {
            REQUIRE(trace_capture.clipboard_file_requests == 8u);
            REQUIRE(
                trace_capture.clipboard_file_inbound_requests ==
                8u);
            REQUIRE(trace_capture.clipboard_file_responses == 8u);
        }
    }
    if (exercise_output_control)
    {
        REQUIRE(output_control_stage == 3);
        REQUIRE(atomic_load_explicit(
                    &platform.refresh_requests,
                    memory_order_acquire) >
                refresh_requests_before);
        REQUIRE(atomic_load_explicit(
                    &platform.output_suppressions,
                    memory_order_acquire) >
                output_suppressions_before);
        REQUIRE(atomic_load_explicit(
                    &platform.output_resumptions,
                    memory_order_acquire) >
                output_resumptions_before);
        REQUIRE(trace_capture.output_suppressions >= 1u);
        REQUIRE(trace_capture.output_resumptions >= 2u);
        REQUIRE(trace_capture.refresh_requests >= 2u);
    }
    if (gateway_profile &&
        gateway_profile->drop_stream != TEST_RDG_STREAM_NONE)
    {
        REQUIRE(gateway_mode == LIBRDP_GATEWAY_RDG_HTTP);
        REQUIRE(rdg_started);
        REQUIRE(test_rdg_gateway_drop_stream(
            &rdg_gateway,
            gateway_profile->drop_stream));
        REQUIRE(atomic_load_explicit(
                    &rdg_gateway.dropped,
                    memory_order_acquire) ==
                (unsigned int)gateway_profile->drop_stream);
        if (gateway_profile->drop_stream == TEST_RDG_STREAM_IN)
        {
            mouse.x++;
            terminal_status =
                librdp_session_send_mouse(session, &mouse);
            REQUIRE(terminal_status == LIBRDP_STATUS_OK ||
                    terminal_status == LIBRDP_STATUS_IO_ERROR ||
                    terminal_status == LIBRDP_STATUS_CLOSED);
        }
        terminal_status = LIBRDP_STATUS_OK;
        for (cycle = 0u; cycle < SMOKE_PUMP_LIMIT; cycle++)
        {
            terminal_status = smoke_client_pump(&runtime);
            if (terminal_status != LIBRDP_STATUS_OK ||
                librdp_session_get_state(session) !=
                    LIBRDP_SESSION_ACTIVE)
                break;
        }
        REQUIRE(cycle < SMOKE_PUMP_LIMIT);
        REQUIRE(terminal_status == LIBRDP_STATUS_IO_ERROR ||
                terminal_status == LIBRDP_STATUS_CLOSED);
        REQUIRE(librdp_session_get_state(session) ==
                LIBRDP_SESSION_FAILED);
        REQUIRE(librdp_session_get_lifecycle(session) ==
                LIBRDP_LIFECYCLE_FAILED);
        REQUIRE(!events.active);
        REQUIRE(events.active_seen);
        REQUIRE(events.error_events == 1u);
        REQUIRE(trace_capture.leaked == 0);
        REQUIRE(librdp_error_info_init(&error_info) ==
                LIBRDP_STATUS_OK);
        REQUIRE(librdp_error_copy_info(
                    librdp_session_last_error(session),
                    &error_info) == LIBRDP_STATUS_OK);
        REQUIRE(error_info.status == terminal_status);
        REQUIRE(error_info.component ==
                LIBRDP_ERROR_COMPONENT_TRANSPORT);
        REQUIRE(error_info.phase != NULL);
        REQUIRE(strcmp(error_info.phase,
                       "client.dispatch") == 0);
        REQUIRE(error_info.trace_id != NULL);
        REQUIRE(strcmp(error_info.trace_id,
                       "server-client-smoke") == 0);
        REQUIRE(client_runtime_disconnect(&runtime) ==
                LIBRDP_STATUS_OK);
        test_rdg_gateway_cancel(&rdg_gateway);
        {
            int gateway_joined =
                test_rdg_gateway_join_status(
                    &rdg_gateway,
                    gateway_profile->expected_fixture_status);

            if (!gateway_joined)
                fprintf(stderr,
                        "RDG fixture join failed actual=%s expected=%s dropped=%u\n",
                        librdp_status_name(rdg_gateway.status),
                        librdp_status_name(
                            gateway_profile
                                ->expected_fixture_status),
                        atomic_load_explicit(
                            &rdg_gateway.dropped,
                            memory_order_acquire));
            REQUIRE(gateway_joined);
        }
        rdg_started = 0;
        test_rdg_gateway_clear(&rdg_gateway);
        REQUIRE(server_host_cancel(host_fixture.host) ==
                LIBRDP_STATUS_OK);
        REQUIRE(pthread_join(host_fixture.thread, NULL) == 0);
        thread_started = 0;
        REQUIRE(host_fixture.status == LIBRDP_STATUS_OK);
        REQUIRE(atomic_load_explicit(&platform.releases,
                                     memory_order_acquire) > 0u);
        result = 0;
        goto cleanup;
    }
    REQUIRE(client_runtime_disconnect(&runtime) == LIBRDP_STATUS_OK);
    if (drive_profile &&
        drive_profile->mode == SMOKE_DRIVE_NOTIFY)
        REQUIRE(smoke_validate_reconnect_lifecycle(
            &trace_capture));
    else
        REQUIRE(smoke_validate_lifecycle(&trace_capture, security));
    if (proxy_started)
    {
        test_http_proxy_cancel(&proxy);
        REQUIRE(test_http_proxy_join(&proxy));
        proxy_started = 0;
        test_http_proxy_clear(&proxy);
    }
    if (rdg_started)
    {
        REQUIRE(test_rdg_gateway_join(&rdg_gateway));
        rdg_started = 0;
        REQUIRE(atomic_load_explicit(&rdg_gateway.closed,
                                     memory_order_acquire) ==
                1u);
        test_rdg_gateway_clear(&rdg_gateway);
    }
    REQUIRE(server_host_cancel(host_fixture.host) == LIBRDP_STATUS_OK);
    REQUIRE(pthread_join(host_fixture.thread, NULL) == 0);
    thread_started = 0;
    REQUIRE(host_fixture.status == LIBRDP_STATUS_OK);
    REQUIRE(strcmp(platform.drive_name, "SMOKE") == 0);
    REQUIRE(atomic_load_explicit(&platform.releases,
                                 memory_order_acquire) > 0u);
    result = 0;

cleanup:
    if (proxy_started)
        test_http_proxy_clear(&proxy);
    if (rdg_started)
        test_rdg_gateway_clear(&rdg_gateway);
    if (thread_started)
    {
        (void)server_host_cancel(host_fixture.host);
        (void)pthread_join(host_fixture.thread, NULL);
    }
    client_runtime_clear(&runtime);
    librdp_session_free(session);
    librdp_settings_free(settings);
    server_host_free(host_fixture.host);
    server_client_clipboard_provider_free(clipboard_provider);
    smoke_drive_confinement_fixture_clear(&drive_confinement);
    if (drive_directory_owned)
    {
        if (drive_marker[0] != '\0')
            (void)unlink(drive_marker);
        if (drive_created[0] != '\0')
            (void)unlink(drive_created);
        if (drive_renamed[0] != '\0')
            (void)unlink(drive_renamed);
        if (drive_notify_first[0] != '\0')
            (void)unlink(drive_notify_first);
        if (drive_notify_late[0] != '\0')
            (void)unlink(drive_notify_late);
        if (drive_notify_directory[0] != '\0')
            (void)rmdir(drive_notify_directory);
        if (drive_directory[0] != '\0')
            (void)rmdir(drive_directory);
    }
    if (cert_path[0] != '\0')
        (void)unlink(cert_path);
    if (key_path[0] != '\0')
        (void)unlink(key_path);
    if (gateway_cert_path[0] != '\0')
        (void)unlink(gateway_cert_path);
    if (gateway_key_path[0] != '\0')
        (void)unlink(gateway_key_path);
    if (curl_environment_changed)
    {
        if (saved_curl_ca_bundle)
            (void)setenv("CURL_CA_BUNDLE",
                         saved_curl_ca_bundle,
                         1);
        else
            (void)unsetenv("CURL_CA_BUNDLE");
    }
    free(saved_curl_ca_bundle);
    return result;
}

static int smoke_run_profile(librdp_security_mode security,
                             librdp_status expected_connect_status,
                             const smoke_nla_identity* identity,
                             const char* bind_address,
                             const char* target,
                             const smoke_gateway_profile* gateway_profile,
                             int exercise_output_control,
                             int cancel_phase,
                             const server_client_clipboard_profile*
                                 clipboard_profile)
{
    return smoke_run_profile_ex(security,
                                expected_connect_status,
                                identity,
                                bind_address,
                                target,
                                gateway_profile,
                                exercise_output_control,
                                cancel_phase,
                                clipboard_profile,
                                NULL,
                                NULL);
}

/*
 * Verify that each pre-authentication security boundary preserves its exact
 * public status, component, phase, native error, and per-session trace ID.
 */
static int smoke_run_security_error(smoke_security_peer_mode peer_mode,
                                    librdp_status expected_status,
                                    int trust_test_certificate,
                                    int use_wrong_pin)
{
    static const char wrong_pin[] =
        "0000000000000000000000000000000000000000000000000000000000000000";
    char cert_path[128] = {0};
    char key_path[128] = {0};
    char* saved_cert_file = NULL;
    const char* current_cert_file = NULL;
    smoke_security_peer fixture;
    smoke_trace_capture trace_capture;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_tls_policy tls_policy;
    librdp_trace_policy trace_policy;
    librdp_error_info error_info;
    uint16_t port = 0u;
    int cert_environment_changed = 0;
    int thread_started = 0;
    int result = 1;

    memset(&fixture, 0, sizeof(fixture));
    memset(&trace_capture, 0, sizeof(trace_capture));
    atomic_init(&fixture.port, 0u);
    atomic_init(&fixture.stop, 0u);
    fixture.mode = peer_mode;
    fixture.status = LIBRDP_STATUS_AGAIN;
    if (peer_mode == SMOKE_SECURITY_PEER_TLS_CERTIFICATE)
    {
        REQUIRE(test_server_make_tls_files(cert_path,
                                           sizeof(cert_path),
                                           key_path,
                                           sizeof(key_path)));
        fixture.certificate_path = cert_path;
        fixture.private_key_path = key_path;
    }
    if (trust_test_certificate)
    {
        current_cert_file = getenv("SSL_CERT_FILE");
        if (current_cert_file)
        {
            saved_cert_file = strdup(current_cert_file);
            REQUIRE(saved_cert_file != NULL);
        }
        REQUIRE(setenv("SSL_CERT_FILE", cert_path, 1) == 0);
        cert_environment_changed = 1;
    }
    REQUIRE(pthread_create(&fixture.thread,
                           NULL,
                           smoke_security_peer_main,
                           &fixture) == 0);
    thread_started = 1;
    REQUIRE(smoke_wait_for_port(&fixture.port, &port));

    settings = librdp_settings_new();
    REQUIRE(settings != NULL);
    REQUIRE(librdp_settings_set_target(settings, "127.0.0.1") ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_port(settings, port) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_security_mode(
                settings,
                peer_mode == SMOKE_SECURITY_PEER_DOWNGRADE
                    ? LIBRDP_SECURITY_AUTO
                    : LIBRDP_SECURITY_TLS) ==
            LIBRDP_STATUS_OK);
    if (peer_mode != SMOKE_SECURITY_PEER_DOWNGRADE)
    {
        REQUIRE(librdp_tls_policy_init(&tls_policy) ==
                LIBRDP_STATUS_OK);
        if (use_wrong_pin)
        {
            tls_policy.mode = LIBRDP_TLS_POLICY_PINNED_FINGERPRINT;
            tls_policy.use_system_store = 0;
            tls_policy.pinned_sha256 = wrong_pin;
        }
        else
        {
            tls_policy.mode =
                peer_mode == SMOKE_SECURITY_PEER_TLS_INVALID
                    ? LIBRDP_TLS_POLICY_INSECURE_LAB
                    : LIBRDP_TLS_POLICY_STRICT;
            tls_policy.use_system_store =
                peer_mode == SMOKE_SECURITY_PEER_TLS_CERTIFICATE ? 1 : 0;
        }
        REQUIRE(librdp_settings_set_tls_policy(settings, &tls_policy) ==
                LIBRDP_STATUS_OK);
    }
    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
    REQUIRE(librdp_trace_policy_init(&trace_policy) ==
            LIBRDP_STATUS_OK);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = smoke_trace_callback;
    trace_policy.callback_user_data = &trace_capture;
    trace_policy.trace_id = "security-boundary";
    trace_capture.target = "127.0.0.1";
    trace_capture.port = port;
    REQUIRE(librdp_session_set_trace_policy(session, &trace_policy) ==
            LIBRDP_STATUS_OK);

    REQUIRE(librdp_session_connect(session) == expected_status);
    REQUIRE(librdp_session_get_state(session) ==
            LIBRDP_SESSION_FAILED);
    REQUIRE(librdp_session_get_lifecycle(session) ==
            LIBRDP_LIFECYCLE_FAILED);
    REQUIRE(trace_capture.records > 0u);
    REQUIRE(trace_capture.connect_starts == 1u);
    REQUIRE(trace_capture.connect_completions == 1u);
    REQUIRE(trace_capture.address_matched);
    REQUIRE(trace_capture.leaked == 0);
    if (peer_mode == SMOKE_SECURITY_PEER_DOWNGRADE)
    {
        REQUIRE(trace_capture.security_downgrades == 1u);
        REQUIRE(trace_capture.tls_connect_failures == 0u);
        REQUIRE(trace_capture.tls_verify_failures == 0u);
    }
    else if (use_wrong_pin)
    {
        REQUIRE(trace_capture.security_downgrades == 0u);
        REQUIRE(trace_capture.tls_connect_failures == 0u);
        REQUIRE(trace_capture.tls_verify_failures == 1u);
    }
    else
    {
        REQUIRE(trace_capture.security_downgrades == 0u);
        REQUIRE(trace_capture.tls_connect_failures == 1u);
        REQUIRE(trace_capture.tls_verify_failures == 0u);
    }
    REQUIRE(librdp_error_info_init(&error_info) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_error_copy_info(librdp_session_last_error(session),
                                   &error_info) == LIBRDP_STATUS_OK);
    REQUIRE(error_info.status == expected_status);
    REQUIRE(error_info.os_errno == 0);
    REQUIRE(error_info.component ==
            (peer_mode == SMOKE_SECURITY_PEER_DOWNGRADE
                 ? LIBRDP_ERROR_COMPONENT_PROTOCOL
                 : LIBRDP_ERROR_COMPONENT_TLS));
    REQUIRE(error_info.phase != NULL);
    REQUIRE(strcmp(error_info.phase,
                   peer_mode == SMOKE_SECURITY_PEER_DOWNGRADE
                       ? "x224.negotiation.policy"
                       : "transport.tls.handshake") == 0);
    REQUIRE(error_info.trace_id != NULL);
    REQUIRE(strcmp(error_info.trace_id,
                   "security-boundary") == 0);
    result = 0;

cleanup:
    atomic_store_explicit(&fixture.stop, 1u, memory_order_release);
    if (thread_started)
    {
        (void)pthread_join(fixture.thread, NULL);
        if (result == 0 && fixture.status != LIBRDP_STATUS_OK)
            result = 1;
    }
    librdp_session_free(session);
    librdp_settings_free(settings);
    if (cert_environment_changed)
    {
        if (saved_cert_file)
            (void)setenv("SSL_CERT_FILE", saved_cert_file, 1);
        else
            (void)unsetenv("SSL_CERT_FILE");
    }
    free(saved_cert_file);
    if (cert_path[0] != '\0')
        (void)unlink(cert_path);
    if (key_path[0] != '\0')
        (void)unlink(key_path);
    return result;
}

/*
 * Exercise server-directed reconnects over both wire envelopes and prove that
 * routing data plus the redirected session ID survive into the next X.224/GCC
 * handshake. Loop mode accepts the protocol maximum and rejects the next hop.
 */
static int smoke_run_redirection(int enhanced, int loop)
{
    char cert_path[128] = {0};
    char key_path[128] = {0};
    smoke_redirection_peer fixture;
    smoke_client_events events;
    smoke_trace_capture trace_capture;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_trace_policy trace_policy;
    librdp_tls_policy tls_policy;
    librdp_metrics metrics;
    librdp_error_info error_info;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0u;
    unsigned int cycle = 0u;
    int thread_started = 0;
    int result = 1;

    memset(&fixture, 0, sizeof(fixture));
    memset(&events, 0, sizeof(events));
    memset(&trace_capture, 0, sizeof(trace_capture));
    atomic_init(&fixture.port, 0u);
    atomic_init(&fixture.stop, 0u);
    atomic_init(&fixture.connections, 0u);
    atomic_init(&fixture.redirects, 0u);
    atomic_init(&fixture.route_verified, 0u);
    fixture.enhanced = enhanced;
    fixture.loop = loop;
    fixture.status = LIBRDP_STATUS_AGAIN;
    REQUIRE(librdp_server_config_init(&fixture.config) ==
            LIBRDP_STATUS_OK);
    fixture.config.bind_address = "127.0.0.1";
    fixture.config.security_mode =
        enhanced ? LIBRDP_SECURITY_TLS : LIBRDP_SECURITY_STANDARD;
    fixture.config.width = SMOKE_WIDTH;
    fixture.config.height = SMOKE_HEIGHT;
    fixture.config.max_peers =
        RDP_SESSION_MAX_SERVER_REDIRECTS + 2u;
    if (enhanced)
    {
        REQUIRE(test_server_make_tls_files_for_host(
            cert_path,
            sizeof(cert_path),
            key_path,
            sizeof(key_path),
            "127.0.0.1"));
        fixture.config.tls_certificate_path = cert_path;
        fixture.config.tls_private_key_path = key_path;
    }
    REQUIRE(pthread_create(&fixture.thread,
                           NULL,
                           smoke_redirection_peer_main,
                           &fixture) == 0);
    thread_started = 1;
    REQUIRE(smoke_wait_for_port(&fixture.port, &port));

    settings = librdp_settings_new();
    REQUIRE(settings != NULL);
    REQUIRE(librdp_settings_set_target(settings, "127.0.0.1") ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_port(settings, port) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_security_mode(
                settings,
                enhanced ? LIBRDP_SECURITY_TLS :
                           LIBRDP_SECURITY_STANDARD) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_desktop_size(settings,
                                             SMOKE_WIDTH,
                                             SMOKE_HEIGHT) ==
            LIBRDP_STATUS_OK);
    if (enhanced)
    {
        REQUIRE(librdp_tls_policy_init(&tls_policy) ==
                LIBRDP_STATUS_OK);
        tls_policy.mode = LIBRDP_TLS_POLICY_INSECURE_LAB;
        tls_policy.use_system_store = 0;
        REQUIRE(librdp_settings_set_tls_policy(settings,
                                               &tls_policy) ==
                LIBRDP_STATUS_OK);
    }
    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
    librdp_session_set_event_callback(session,
                                      smoke_client_event,
                                      &events);
    REQUIRE(librdp_trace_policy_init(&trace_policy) ==
            LIBRDP_STATUS_OK);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = smoke_trace_callback;
    trace_policy.callback_user_data = &trace_capture;
    trace_policy.trace_id =
        loop ? "redirection-loop" :
               enhanced ? "redirection-tls" :
                          "redirection-standard";
    trace_capture.target = "127.0.0.1";
    trace_capture.port = port;
    REQUIRE(librdp_session_set_trace_policy(session,
                                            &trace_policy) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_session_connect(session) == LIBRDP_STATUS_OK);

    for (cycle = 0u; cycle < SMOKE_PUMP_LIMIT; cycle++)
    {
        status = librdp_session_run_once(session, 50);
        if (loop && status == LIBRDP_STATUS_LIMIT_EXCEEDED)
            break;
        REQUIRE(status == LIBRDP_STATUS_OK ||
                status == LIBRDP_STATUS_TIMEOUT);
        if (!loop &&
            atomic_load_explicit(&fixture.route_verified,
                                 memory_order_acquire) == 1u &&
            librdp_session_get_state(session) ==
                LIBRDP_SESSION_ACTIVE)
            break;
    }
    REQUIRE(cycle < SMOKE_PUMP_LIMIT);
    REQUIRE(librdp_metrics_init(&metrics) == LIBRDP_STATUS_OK);
    REQUIRE(librdp_session_get_metrics(session, &metrics) ==
            LIBRDP_STATUS_OK);
    REQUIRE(atomic_load_explicit(&fixture.route_verified,
                                 memory_order_acquire) == 1u);
    REQUIRE(trace_capture.leaked == 0);
    if (loop)
    {
        REQUIRE(status == LIBRDP_STATUS_LIMIT_EXCEEDED);
        REQUIRE(smoke_wait_for_counter(
            &fixture.redirects,
            RDP_SESSION_MAX_SERVER_REDIRECTS + 1u));
        REQUIRE(atomic_load_explicit(&fixture.connections,
                                     memory_order_acquire) ==
                RDP_SESSION_MAX_SERVER_REDIRECTS + 1u);
        REQUIRE(atomic_load_explicit(&fixture.redirects,
                                     memory_order_acquire) ==
                RDP_SESSION_MAX_SERVER_REDIRECTS + 1u);
        REQUIRE(metrics.reconnects ==
                RDP_SESSION_MAX_SERVER_REDIRECTS);
        REQUIRE(metrics.limits_rejected == 1u);
        REQUIRE(trace_capture.redirections ==
                RDP_SESSION_MAX_SERVER_REDIRECTS);
        REQUIRE(trace_capture.redirection_reconnects ==
                RDP_SESSION_MAX_SERVER_REDIRECTS);
        REQUIRE(trace_capture.redirection_loops == 1u);
        REQUIRE(librdp_error_info_init(&error_info) ==
                LIBRDP_STATUS_OK);
        REQUIRE(librdp_error_copy_info(
                    librdp_session_last_error(session),
                    &error_info) == LIBRDP_STATUS_OK);
        REQUIRE(error_info.status == LIBRDP_STATUS_LIMIT_EXCEEDED);
        REQUIRE(error_info.component ==
                LIBRDP_ERROR_COMPONENT_PROTOCOL);
        REQUIRE(error_info.phase != NULL &&
                strcmp(error_info.phase,
                       "client.redirection.loop") == 0);
    }
    else
    {
        REQUIRE(status == LIBRDP_STATUS_OK ||
                status == LIBRDP_STATUS_TIMEOUT);
        REQUIRE(atomic_load_explicit(&fixture.connections,
                                     memory_order_acquire) == 2u);
        REQUIRE(atomic_load_explicit(&fixture.redirects,
                                     memory_order_acquire) == 1u);
        REQUIRE(metrics.reconnects == 1u);
        REQUIRE(metrics.limits_rejected == 0u);
        REQUIRE(trace_capture.redirections == 1u);
        REQUIRE(trace_capture.redirection_reconnects == 1u);
        REQUIRE(trace_capture.redirection_loops == 0u);
        REQUIRE(trace_capture.connect_starts == 2u);
        REQUIRE(trace_capture.connect_completions == 2u);
        REQUIRE(librdp_session_get_state(session) ==
                LIBRDP_SESSION_ACTIVE);
        REQUIRE(events.active);
        REQUIRE(events.error_events == 0u);
    }
    REQUIRE(librdp_session_disconnect(session) ==
            LIBRDP_STATUS_OK);
    result = 0;

cleanup:
    atomic_store_explicit(&fixture.stop, 1u, memory_order_release);
    if (thread_started)
    {
        (void)pthread_join(fixture.thread, NULL);
        if (result == 0 && fixture.status != LIBRDP_STATUS_OK)
            result = 1;
    }
    librdp_session_free(session);
    librdp_settings_free(settings);
    if (cert_path[0] != '\0')
        (void)unlink(cert_path);
    if (key_path[0] != '\0')
        (void)unlink(key_path);
    return result;
}

typedef struct smoke_resource_snapshot
{
    size_t descriptor_count;
    size_t thread_count;
    uint64_t resident_bytes;
    int thread_count_available;
    int resident_bytes_available;
} smoke_resource_snapshot;

/*
 * Prefer procfs for constant-time descriptor accounting, then fall back to a
 * bounded POSIX descriptor scan on systems without procfs.
 */
static int smoke_count_descriptors(size_t* count)
{
    DIR* directory = NULL;
    struct dirent* entry = NULL;
    size_t total = 0u;
    long descriptor_limit = 0;
    int descriptor = 0;

    if (!count)
        return 0;
    directory = opendir("/proc/self/fd");
    if (directory)
    {
        while ((entry = readdir(directory)) != NULL)
        {
            if (strcmp(entry->d_name, ".") != 0 &&
                strcmp(entry->d_name, "..") != 0)
                total++;
        }
        (void)closedir(directory);
        if (total == 0u)
            return 0;
        *count = total - 1u;
        return 1;
    }

    descriptor_limit = sysconf(_SC_OPEN_MAX);
    if (descriptor_limit <= 0)
        return 0;
    if (descriptor_limit > SMOKE_DESCRIPTOR_SCAN_LIMIT)
        descriptor_limit = SMOKE_DESCRIPTOR_SCAN_LIMIT;
    for (descriptor = 0;
         (long)descriptor < descriptor_limit;
         descriptor++)
    {
        errno = 0;
        if (fcntl(descriptor, F_GETFD) >= 0 || errno != EBADF)
            total++;
    }
    *count = total;
    return 1;
}

/*
 * Procfs provides current thread and resident-memory observations on Linux.
 * Other supported systems still receive portable descriptor checks and run
 * this same loop under leak sanitizers in their configured test jobs.
 */
static void smoke_read_optional_process_resources(
    smoke_resource_snapshot* snapshot)
{
    DIR* directory = NULL;
    struct dirent* entry = NULL;
#if !SMOKE_ADDRESS_SANITIZER_ACTIVE
    FILE* statm = NULL;
    unsigned long long virtual_pages = 0u;
    unsigned long long resident_pages = 0u;
    long page_size = 0;
#endif

    directory = opendir("/proc/self/task");
    if (directory)
    {
        while ((entry = readdir(directory)) != NULL)
        {
            if (strcmp(entry->d_name, ".") != 0 &&
                strcmp(entry->d_name, "..") != 0)
                snapshot->thread_count++;
        }
        (void)closedir(directory);
        snapshot->thread_count_available = 1;
    }

#if !SMOKE_ADDRESS_SANITIZER_ACTIVE
    statm = fopen("/proc/self/statm", "r");
    if (!statm)
        return;
    page_size = sysconf(_SC_PAGESIZE);
    if (page_size > 0 &&
        fscanf(statm,
               "%llu %llu",
               &virtual_pages,
               &resident_pages) == 2 &&
        resident_pages <= UINT64_MAX / (uint64_t)page_size)
    {
        snapshot->resident_bytes =
            (uint64_t)resident_pages * (uint64_t)page_size;
        snapshot->resident_bytes_available = 1;
    }
    (void)virtual_pages;
    (void)fclose(statm);
#endif
}

static int smoke_take_resource_snapshot(smoke_resource_snapshot* snapshot)
{
    if (!snapshot)
        return 0;
    memset(snapshot, 0, sizeof(*snapshot));
    if (!smoke_count_descriptors(&snapshot->descriptor_count))
        return 0;
    smoke_read_optional_process_resources(snapshot);
    return 1;
}

/*
 * A joined Linux task can remain visible through procfs for a short interval
 * after its child TID has been cleared. Require the exact baseline within a
 * bounded interval so persistent worker leaks still fail deterministically.
 */
static int smoke_wait_for_thread_quiescence(
    size_t expected_thread_count,
    smoke_resource_snapshot* snapshot)
{
    const struct timespec delay = {0, 2000000l};
    unsigned int attempt = 0u;

    if (!snapshot)
        return 0;
    for (attempt = 0u; attempt < 50u; attempt++)
    {
        if (!smoke_take_resource_snapshot(snapshot))
            return 0;
        if (!snapshot->thread_count_available ||
            snapshot->thread_count == expected_thread_count)
            return 1;
        (void)nanosleep(&delay, NULL);
    }
    return 1;
}

/*
 * Alternate all client security paths, tear every fixture down completely,
 * and periodically include a protocol-driven reconnect. Exact descriptor and
 * thread baselines catch leaked transports or workers; bounded resident growth
 * complements the allocator-level sanitizer run.
 */
static int smoke_run_lifecycle_stress(void)
{
    smoke_resource_snapshot baseline;
    smoke_resource_snapshot current;
    uint64_t resident_floor = 0u;
    unsigned int cycle = 0u;

    CHECK(smoke_take_resource_snapshot(&baseline));
    for (cycle = 0u;
         cycle < SMOKE_LIFECYCLE_STRESS_CYCLES;
         cycle++)
    {
        librdp_security_mode security = LIBRDP_SECURITY_STANDARD;
        const smoke_nla_identity* identity = NULL;

        if (cycle % 3u == 1u)
            security = LIBRDP_SECURITY_TLS;
        else if (cycle % 3u == 2u)
        {
            security = LIBRDP_SECURITY_NLA;
            identity = &smoke_nla_default_identity;
        }
        CHECK(smoke_run_profile(security,
                                LIBRDP_STATUS_OK,
                                identity,
                                "127.0.0.1",
                                "127.0.0.1",
                                NULL,
                                0,
                                -1,
                                NULL) == 0);
        if (cycle % 6u == 5u)
            CHECK(smoke_run_redirection((cycle / 6u) % 2u, 0) == 0);

        CHECK(smoke_wait_for_thread_quiescence(
            baseline.thread_count,
            &current));
        if (current.descriptor_count != baseline.descriptor_count)
        {
            fprintf(stderr,
                    "lifecycle stress descriptor growth cycle=%u baseline=%llu current=%llu\n",
                    cycle,
                    (unsigned long long)baseline.descriptor_count,
                    (unsigned long long)current.descriptor_count);
            return 1;
        }
        if (baseline.thread_count_available &&
            current.thread_count_available &&
            current.thread_count != baseline.thread_count)
        {
            fprintf(stderr,
                    "lifecycle stress thread growth cycle=%u baseline=%llu current=%llu\n",
                    cycle,
                    (unsigned long long)baseline.thread_count,
                    (unsigned long long)current.thread_count);
            return 1;
        }
        if (current.resident_bytes_available &&
            cycle == SMOKE_LIFECYCLE_STRESS_WARMUP_CYCLES)
            resident_floor = current.resident_bytes;
        else if (current.resident_bytes_available &&
                 cycle > SMOKE_LIFECYCLE_STRESS_WARMUP_CYCLES)
        {
            if (current.resident_bytes < resident_floor)
                resident_floor = current.resident_bytes;
            if (current.resident_bytes >
                resident_floor +
                    SMOKE_LIFECYCLE_STRESS_RSS_ALLOWANCE)
            {
                fprintf(stderr,
                        "lifecycle stress resident growth cycle=%u floor=%llu current=%llu\n",
                        cycle,
                        (unsigned long long)resident_floor,
                        (unsigned long long)current.resident_bytes);
                return 1;
            }
        }
    }
    return 0;
}

/*
 * Hold a real NLA server immediately after TLS so the client must expire its
 * CredSSP challenge read. The fixture also verifies phase attribution and that
 * identity material never reaches the session trace callback.
 */
static int smoke_run_credssp_timeout(void)
{
    const smoke_nla_identity* identity = &smoke_nla_default_identity;
    char cert_path[128] = {0};
    char key_path[128] = {0};
    smoke_nla_stall fixture;
    smoke_trace_capture trace_capture;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_tls_policy tls_policy;
    librdp_trace_policy trace_policy;
    librdp_error_info error_info;
    uint16_t port = 0u;
    int thread_started = 0;
    int result = 1;

    memset(&fixture, 0, sizeof(fixture));
    memset(&trace_capture, 0, sizeof(trace_capture));
    trace_capture.identity = identity;
    atomic_init(&fixture.port, 0u);
    atomic_init(&fixture.stop, 0u);
    atomic_init(&fixture.authenticating, 0u);
    REQUIRE(test_server_make_tls_files(cert_path,
                                       sizeof(cert_path),
                                       key_path,
                                       sizeof(key_path)));
    REQUIRE(librdp_server_config_init(&fixture.config) ==
            LIBRDP_STATUS_OK);
    fixture.config.bind_address = "127.0.0.1";
    fixture.config.security_mode = LIBRDP_SECURITY_NLA;
    fixture.config.tls_certificate_path = cert_path;
    fixture.config.tls_private_key_path = key_path;
    fixture.config.nla_domain = identity->domain;
    fixture.config.nla_username = identity->username;
    fixture.config.nla_password = identity->password;
    REQUIRE(pthread_create(&fixture.thread,
                           NULL,
                           smoke_nla_stall_main,
                           &fixture) == 0);
    thread_started = 1;
    REQUIRE(smoke_wait_for_port(&fixture.port, &port));

    settings = librdp_settings_new();
    REQUIRE(settings != NULL);
    REQUIRE(librdp_settings_set_target(settings, "127.0.0.1") ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_port(settings, port) == LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_security_mode(settings,
                                              LIBRDP_SECURITY_NLA) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_username(settings, identity->username) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_password(settings, identity->password) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_domain(settings, identity->domain) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_tls_policy_init(&tls_policy) == LIBRDP_STATUS_OK);
    tls_policy.mode = LIBRDP_TLS_POLICY_INSECURE_LAB;
    tls_policy.use_system_store = 0;
    REQUIRE(librdp_settings_set_tls_policy(settings, &tls_policy) ==
            LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
    REQUIRE(librdp_trace_policy_init(&trace_policy) == LIBRDP_STATUS_OK);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = smoke_trace_callback;
    trace_policy.callback_user_data = &trace_capture;
    trace_policy.trace_id = "credssp-timeout";
    trace_capture.target = "127.0.0.1";
    trace_capture.port = port;
    REQUIRE(librdp_session_set_trace_policy(session, &trace_policy) ==
            LIBRDP_STATUS_OK);

    REQUIRE(librdp_session_connect(session) == LIBRDP_STATUS_TIMEOUT);
    REQUIRE(atomic_load_explicit(&fixture.authenticating,
                                 memory_order_acquire) == 1u);
    REQUIRE(trace_capture.records > 0u);
    REQUIRE(trace_capture.connect_starts == 1u);
    REQUIRE(trace_capture.connect_completions == 1u);
    REQUIRE(trace_capture.address_matched);
    REQUIRE(trace_capture.credssp_failures == 1u);
    REQUIRE(trace_capture.leaked == 0);
    REQUIRE(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    REQUIRE(librdp_error_info_init(&error_info) == LIBRDP_STATUS_OK);
    REQUIRE(librdp_error_copy_info(librdp_session_last_error(session),
                                   &error_info) == LIBRDP_STATUS_OK);
    REQUIRE(error_info.status == LIBRDP_STATUS_TIMEOUT);
    REQUIRE(error_info.os_errno == 0);
    REQUIRE(error_info.component == LIBRDP_ERROR_COMPONENT_CREDSSP);
    REQUIRE(error_info.phase != NULL);
    REQUIRE(strcmp(error_info.phase,
                   "credssp.nla.challenge.read") == 0);
    REQUIRE(error_info.trace_id != NULL);
    REQUIRE(strcmp(error_info.trace_id, "credssp-timeout") == 0);
    result = 0;

cleanup:
    atomic_store_explicit(&fixture.stop, 1u, memory_order_release);
    if (thread_started)
        (void)pthread_join(fixture.thread, NULL);
    if (result == 0 && fixture.status != LIBRDP_STATUS_OK)
        result = 1;
    librdp_session_free(session);
    librdp_settings_free(settings);
    if (cert_path[0] != '\0')
        (void)unlink(cert_path);
    if (key_path[0] != '\0')
        (void)unlink(key_path);
    return result;
}

/*
 * Drive one corrupted Standard Security packet through the public client
 * lifecycle. The peer must observe EOF, no decoded update may be delivered,
 * and the trace must identify the constant-time MAC rejection boundary.
 */
static int smoke_run_integrity_case(smoke_integrity_tamper tamper)
{
    smoke_integrity_peer fixture;
    smoke_client_events events;
    smoke_trace_capture trace_capture;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_trace_policy trace_policy;
    librdp_error_info error_info;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0u;
    unsigned int cycle = 0u;
    unsigned int surface_events_before_failure = 0u;
    int thread_started = 0;
    int result = 1;

    memset(&fixture, 0, sizeof(fixture));
    memset(&events, 0, sizeof(events));
    memset(&trace_capture, 0, sizeof(trace_capture));
    atomic_init(&fixture.port, 0u);
    atomic_init(&fixture.packet_sent, 0u);
    atomic_init(&fixture.client_closed, 0u);
    fixture.tamper = tamper;
    fixture.status = LIBRDP_STATUS_AGAIN;
    REQUIRE(librdp_server_config_init(&fixture.config) ==
            LIBRDP_STATUS_OK);
    fixture.config.bind_address = "127.0.0.1";
    fixture.config.security_mode = LIBRDP_SECURITY_STANDARD;
    fixture.config.width = SMOKE_WIDTH;
    fixture.config.height = SMOKE_HEIGHT;
    REQUIRE(pthread_create(&fixture.thread,
                           NULL,
                           smoke_integrity_peer_main,
                           &fixture) == 0);
    thread_started = 1;
    REQUIRE(smoke_wait_for_port(&fixture.port, &port));

    settings = librdp_settings_new();
    REQUIRE(settings != NULL);
    REQUIRE(librdp_settings_set_target(settings, "127.0.0.1") ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_port(settings, port) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_security_mode(
                settings,
                LIBRDP_SECURITY_STANDARD) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_desktop_size(settings,
                                             SMOKE_WIDTH,
                                             SMOKE_HEIGHT) ==
            LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
    librdp_session_set_event_callback(session,
                                      smoke_client_event,
                                      &events);
    REQUIRE(librdp_trace_policy_init(&trace_policy) ==
            LIBRDP_STATUS_OK);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = smoke_trace_callback;
    trace_policy.callback_user_data = &trace_capture;
    trace_policy.trace_id = "standard-integrity";
    trace_capture.target = "127.0.0.1";
    trace_capture.port = port;
    REQUIRE(librdp_session_set_trace_policy(session,
                                            &trace_policy) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (cycle = 0u; cycle < SMOKE_PUMP_LIMIT; cycle++)
    {
        status = librdp_session_run_once(session, 50);
        if (status == LIBRDP_STATUS_PROTOCOL_ERROR)
            break;
        REQUIRE(status == LIBRDP_STATUS_OK);
        if (events.active_seen)
            surface_events_before_failure = events.surface_events;
    }
    REQUIRE(cycle < SMOKE_PUMP_LIMIT);
    REQUIRE(status == LIBRDP_STATUS_PROTOCOL_ERROR);
    REQUIRE(events.active_seen);
    REQUIRE(events.error_events == 1u);
    REQUIRE(events.surface_events == surface_events_before_failure);
    REQUIRE(librdp_session_get_state(session) ==
            LIBRDP_SESSION_FAILED);
    REQUIRE(librdp_session_get_lifecycle(session) ==
            LIBRDP_LIFECYCLE_FAILED);
    REQUIRE(trace_capture.integrity_failures == 1u);
    if (tamper == SMOKE_INTEGRITY_FASTPATH_MAC)
    {
        REQUIRE(trace_capture.fastpath_integrity_failures == 1u);
        REQUIRE(trace_capture.slowpath_integrity_failures == 0u);
    }
    else
    {
        REQUIRE(trace_capture.slowpath_integrity_failures == 1u);
        REQUIRE(trace_capture.fastpath_integrity_failures == 0u);
    }
    REQUIRE(librdp_error_info_init(&error_info) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_error_copy_info(
                librdp_session_last_error(session),
                &error_info) == LIBRDP_STATUS_OK);
    REQUIRE(error_info.status == LIBRDP_STATUS_PROTOCOL_ERROR);
    REQUIRE(error_info.os_errno == 0);
    REQUIRE(error_info.component ==
            LIBRDP_ERROR_COMPONENT_PROTOCOL);
    REQUIRE(error_info.phase != NULL);
    REQUIRE(strcmp(error_info.phase,
                   tamper == SMOKE_INTEGRITY_FASTPATH_MAC
                       ? "rdp.fastpath.security"
                       : "rdp.slowpath.security") == 0);
    REQUIRE(error_info.trace_id != NULL);
    REQUIRE(strcmp(error_info.trace_id,
                   "standard-integrity") == 0);
    REQUIRE(pthread_join(fixture.thread, NULL) == 0);
    thread_started = 0;
    REQUIRE(fixture.status == LIBRDP_STATUS_OK);
    REQUIRE(atomic_load_explicit(&fixture.packet_sent,
                                 memory_order_acquire) == 1u);
    REQUIRE(atomic_load_explicit(&fixture.client_closed,
                                 memory_order_acquire) == 1u);
    result = 0;

cleanup:
    librdp_session_free(session);
    session = NULL;
    if (thread_started)
        (void)pthread_join(fixture.thread, NULL);
    librdp_settings_free(settings);
    return result;
}

static int smoke_run_standard_integrity(void)
{
    static const smoke_integrity_tamper cases[] = {
        SMOKE_INTEGRITY_SLOWPATH_MAC,
        SMOKE_INTEGRITY_FASTPATH_MAC,
        SMOKE_INTEGRITY_SLOWPATH_CIPHERTEXT
    };
    size_t index = 0u;

    for (index = 0u;
         index < sizeof(cases) / sizeof(cases[0]);
         index++)
    {
        if (smoke_run_integrity_case(cases[index]) != 0)
            return 1;
    }
    return 0;
}

/*
 * Verify authenticated fast-path delivery against a whole-frame golden hash.
 * The fixture exercises raw and RLE bitmap rectangles through the public
 * client runtime rather than direct parser calls.
 */
static int smoke_run_fastpath_bitmap(void)
{
    smoke_fastpath_peer fixture;
    smoke_client_events events;
    smoke_trace_capture trace_capture;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_trace_policy trace_policy;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0u;
    unsigned int cycle = 0u;
    int thread_started = 0;
    int result = 1;

    memset(&fixture, 0, sizeof(fixture));
    memset(&events, 0, sizeof(events));
    memset(&trace_capture, 0, sizeof(trace_capture));
    atomic_init(&fixture.port, 0u);
    atomic_init(&fixture.packet_sent, 0u);
    atomic_init(&fixture.client_closed, 0u);
    fixture.send = smoke_fastpath_bitmap_send;
    fixture.status = LIBRDP_STATUS_AGAIN;
    REQUIRE(librdp_server_config_init(&fixture.config) ==
            LIBRDP_STATUS_OK);
    fixture.config.bind_address = "127.0.0.1";
    fixture.config.security_mode = LIBRDP_SECURITY_STANDARD;
    fixture.config.width = SMOKE_WIDTH;
    fixture.config.height = SMOKE_HEIGHT;
    REQUIRE(pthread_create(&fixture.thread,
                           NULL,
                           smoke_fastpath_peer_main,
                           &fixture) == 0);
    thread_started = 1;
    REQUIRE(smoke_wait_for_port(&fixture.port, &port));

    settings = librdp_settings_new();
    REQUIRE(settings != NULL);
    REQUIRE(librdp_settings_set_target(settings, "127.0.0.1") ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_port(settings, port) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_security_mode(
                settings,
                LIBRDP_SECURITY_STANDARD) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_desktop_size(settings,
                                             SMOKE_WIDTH,
                                             SMOKE_HEIGHT) ==
            LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
    librdp_session_set_event_callback(session,
                                      smoke_client_event,
                                      &events);
    REQUIRE(librdp_trace_policy_init(&trace_policy) ==
            LIBRDP_STATUS_OK);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = smoke_trace_callback;
    trace_policy.callback_user_data = &trace_capture;
    trace_policy.trace_id = "fastpath-bitmap";
    trace_capture.target = "127.0.0.1";
    trace_capture.port = port;
    REQUIRE(librdp_session_set_trace_policy(session,
                                            &trace_policy) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (cycle = 0u; cycle < SMOKE_PUMP_LIMIT; cycle++)
    {
        status = librdp_session_run_once(session, 50);
        REQUIRE(status == LIBRDP_STATUS_OK);
        if (events.active_seen &&
            events.surface_events >= 2u &&
            trace_capture.fastpath_bitmap_updates == 1u)
            break;
    }
    REQUIRE(cycle < SMOKE_PUMP_LIMIT);
    REQUIRE(events.active);
    REQUIRE(events.error_events == 0u);
    REQUIRE(events.surface_events >= 2u);
    REQUIRE(trace_capture.fastpath_bitmap_updates == 1u);
    REQUIRE(trace_capture.slowpath_bitmap_updates == 0u);
    REQUIRE(trace_capture.integrity_failures == 0u);
    REQUIRE(trace_capture.fastpath_integrity_failures == 0u);
    REQUIRE(smoke_frame_matches_sha256(
        librdp_surface_pixels(librdp_session_get_surface(session)),
        (size_t)librdp_surface_stride(
            librdp_session_get_surface(session)) *
            librdp_surface_height(
                librdp_session_get_surface(session)),
        smoke_fastpath_bitmap_sha256));
    REQUIRE(librdp_session_disconnect(session) ==
            LIBRDP_STATUS_OK);
    REQUIRE(pthread_join(fixture.thread, NULL) == 0);
    thread_started = 0;
    REQUIRE(fixture.status == LIBRDP_STATUS_OK);
    REQUIRE(atomic_load_explicit(&fixture.packet_sent,
                                 memory_order_acquire) == 1u);
    REQUIRE(atomic_load_explicit(&fixture.client_closed,
                                 memory_order_acquire) == 1u);
    result = 0;

cleanup:
    librdp_session_free(session);
    session = NULL;
    if (thread_started)
        (void)pthread_join(fixture.thread, NULL);
    librdp_settings_free(settings);
    return result;
}

static int smoke_nscodec_edge_matches(
    const librdp_surface* surface)
{
    static const uint8_t expected_luma[3][3] = {
        {0x46u, 0x50u, 0x5au},
        {0x28u, 0x32u, 0x3cu},
        {0x0au, 0x14u, 0x1eu}
    };
    const uint8_t* pixels = NULL;
    size_t stride = 0u;
    uint32_t row = 0u;
    uint32_t column = 0u;

    if (!surface ||
        librdp_surface_width(surface) != SMOKE_WIDTH ||
        librdp_surface_height(surface) != SMOKE_HEIGHT)
        return 0;
    pixels = librdp_surface_pixels(surface);
    stride = librdp_surface_stride(surface);
    if (!pixels || stride <= 3u * 4u)
        return 0;
    for (row = 0u; row < 3u; row++)
    {
        for (column = 0u; column < 3u; column++)
        {
            const uint8_t* pixel =
                pixels +
                ((size_t)(SMOKE_HEIGHT - 3u + row) * stride) +
                ((size_t)(SMOKE_WIDTH - 3u + column) * 4u);
            uint8_t expected = expected_luma[row][column];

            if (pixel[0] != expected ||
                pixel[1] != expected ||
                pixel[2] != expected ||
                pixel[3] != 0xffu)
                return 0;
        }
    }
    pixels += ((size_t)(SMOKE_HEIGHT - 3u) * stride) +
              ((size_t)(SMOKE_WIDTH - 4u) * 4u);
    return pixels[0] == 0u &&
           pixels[1] == 0u &&
           pixels[2] == 0u;
}

/*
 * Drive an odd-sized NSCodec Surface Bits command through encrypted
 * fast-path and verify its edge placement on the normalized framebuffer.
 */
static int smoke_run_fastpath_nscodec(void)
{
    smoke_fastpath_peer fixture;
    smoke_client_events events;
    smoke_trace_capture trace_capture;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_trace_policy trace_policy;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0u;
    unsigned int cycle = 0u;
    int thread_started = 0;
    int result = 1;

    memset(&fixture, 0, sizeof(fixture));
    memset(&events, 0, sizeof(events));
    memset(&trace_capture, 0, sizeof(trace_capture));
    atomic_init(&fixture.port, 0u);
    atomic_init(&fixture.packet_sent, 0u);
    atomic_init(&fixture.client_closed, 0u);
    fixture.send = smoke_fastpath_nscodec_send;
    fixture.status = LIBRDP_STATUS_AGAIN;
    REQUIRE(librdp_server_config_init(&fixture.config) ==
            LIBRDP_STATUS_OK);
    fixture.config.bind_address = "127.0.0.1";
    fixture.config.security_mode = LIBRDP_SECURITY_STANDARD;
    fixture.config.width = SMOKE_WIDTH;
    fixture.config.height = SMOKE_HEIGHT;
    REQUIRE(pthread_create(&fixture.thread,
                           NULL,
                           smoke_fastpath_peer_main,
                           &fixture) == 0);
    thread_started = 1;
    REQUIRE(smoke_wait_for_port(&fixture.port, &port));

    settings = librdp_settings_new();
    REQUIRE(settings != NULL);
    REQUIRE(librdp_settings_set_target(settings, "127.0.0.1") ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_port(settings, port) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_security_mode(
                settings,
                LIBRDP_SECURITY_STANDARD) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_desktop_size(settings,
                                             SMOKE_WIDTH,
                                             SMOKE_HEIGHT) ==
            LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
    librdp_session_set_event_callback(session,
                                      smoke_client_event,
                                      &events);
    REQUIRE(librdp_trace_policy_init(&trace_policy) ==
            LIBRDP_STATUS_OK);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = smoke_trace_callback;
    trace_policy.callback_user_data = &trace_capture;
    trace_policy.trace_id = "fastpath-nscodec";
    trace_capture.target = "127.0.0.1";
    trace_capture.port = port;
    REQUIRE(librdp_session_set_trace_policy(session,
                                            &trace_policy) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (cycle = 0u; cycle < SMOKE_PUMP_LIMIT; cycle++)
    {
        status = librdp_session_run_once(session, 50);
        REQUIRE(status == LIBRDP_STATUS_OK);
        if (events.active_seen &&
            events.surface_events >= 2u &&
            trace_capture.surface_nscodec_updates == 1u)
            break;
    }
    REQUIRE(cycle < SMOKE_PUMP_LIMIT);
    REQUIRE(events.active);
    REQUIRE(events.error_events == 0u);
    REQUIRE(events.surface_events >= 2u);
    REQUIRE(trace_capture.surface_nscodec_updates == 1u);
    REQUIRE(trace_capture.integrity_failures == 0u);
    REQUIRE(trace_capture.fastpath_integrity_failures == 0u);
    REQUIRE(smoke_nscodec_edge_matches(
        librdp_session_get_surface(session)));
    REQUIRE(librdp_session_disconnect(session) ==
            LIBRDP_STATUS_OK);
    REQUIRE(pthread_join(fixture.thread, NULL) == 0);
    thread_started = 0;
    REQUIRE(fixture.status == LIBRDP_STATUS_OK);
    REQUIRE(atomic_load_explicit(&fixture.packet_sent,
                                 memory_order_acquire) == 1u);
    REQUIRE(atomic_load_explicit(&fixture.client_closed,
                                 memory_order_acquire) == 1u);
    result = 0;

cleanup:
    librdp_session_free(session);
    session = NULL;
    if (thread_started)
        (void)pthread_join(fixture.thread, NULL);
    librdp_settings_free(settings);
    return result;
}

static int smoke_rfx_surface_matches(
    const librdp_surface* surface)
{
    const uint8_t* pixels = NULL;
    size_t stride = 0u;
    uint32_t y = 0u;
    uint32_t x = 0u;

    if (!surface ||
        librdp_surface_width(surface) != SMOKE_WIDTH ||
        librdp_surface_height(surface) != SMOKE_HEIGHT)
        return 0;
    pixels = librdp_surface_pixels(surface);
    stride = librdp_surface_stride(surface);
    if (!pixels || stride != (size_t)SMOKE_WIDTH * 4u)
        return 0;

    for (y = 0u; y < SMOKE_HEIGHT; y++)
    {
        for (x = 0u; x < SMOKE_WIDTH; x++)
        {
            const uint8_t* pixel =
                pixels + ((size_t)y * stride) + ((size_t)x * 4u);
            int written =
                (x < 64u && y < 64u) ||
                (x >= 64u && x < 192u &&
                 y >= 64u && y < 128u);

            if (written)
            {
                if (pixel[0] != 128u ||
                    pixel[1] != 128u ||
                    pixel[2] != 128u ||
                    pixel[3] != 0xffu)
                    return 0;
            }
            else if (pixel[0] != 0u ||
                     pixel[1] != 0u ||
                     pixel[2] != 0u ||
                     pixel[3] != 0u)
                return 0;
        }
    }
    return 1;
}

/*
 * Decode independent single- and multi-tile RemoteFX frames through Surface
 * Commands and verify every destination and untouched framebuffer pixel.
 */
static int smoke_run_fastpath_rfx(void)
{
    smoke_fastpath_peer fixture;
    smoke_client_events events;
    smoke_trace_capture trace_capture;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_trace_policy trace_policy;
    librdp_status status = LIBRDP_STATUS_OK;
    uint16_t port = 0u;
    unsigned int cycle = 0u;
    int thread_started = 0;
    int result = 1;

    memset(&fixture, 0, sizeof(fixture));
    memset(&events, 0, sizeof(events));
    memset(&trace_capture, 0, sizeof(trace_capture));
    atomic_init(&fixture.port, 0u);
    atomic_init(&fixture.packet_sent, 0u);
    atomic_init(&fixture.client_closed, 0u);
    fixture.send = smoke_fastpath_rfx_send;
    fixture.status = LIBRDP_STATUS_AGAIN;
    REQUIRE(librdp_server_config_init(&fixture.config) ==
            LIBRDP_STATUS_OK);
    fixture.config.bind_address = "127.0.0.1";
    fixture.config.security_mode = LIBRDP_SECURITY_STANDARD;
    fixture.config.width = SMOKE_WIDTH;
    fixture.config.height = SMOKE_HEIGHT;
    REQUIRE(pthread_create(&fixture.thread,
                           NULL,
                           smoke_fastpath_peer_main,
                           &fixture) == 0);
    thread_started = 1;
    REQUIRE(smoke_wait_for_port(&fixture.port, &port));

    settings = librdp_settings_new();
    REQUIRE(settings != NULL);
    REQUIRE(librdp_settings_set_target(settings, "127.0.0.1") ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_port(settings, port) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_security_mode(
                settings,
                LIBRDP_SECURITY_STANDARD) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_desktop_size(settings,
                                             SMOKE_WIDTH,
                                             SMOKE_HEIGHT) ==
            LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
    librdp_session_set_event_callback(session,
                                      smoke_client_event,
                                      &events);
    REQUIRE(librdp_trace_policy_init(&trace_policy) ==
            LIBRDP_STATUS_OK);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = smoke_trace_callback;
    trace_policy.callback_user_data = &trace_capture;
    trace_policy.trace_id = "fastpath-rfx";
    trace_capture.target = "127.0.0.1";
    trace_capture.port = port;
    REQUIRE(librdp_session_set_trace_policy(session,
                                            &trace_policy) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (cycle = 0u; cycle < SMOKE_PUMP_LIMIT; cycle++)
    {
        status = librdp_session_run_once(session, 50);
        REQUIRE(status == LIBRDP_STATUS_OK);
        if (events.active_seen &&
            trace_capture.surface_rfx_updates == 2u &&
            trace_capture.surface_rfx_tiles == 3u)
            break;
    }
    REQUIRE(cycle < SMOKE_PUMP_LIMIT);
    REQUIRE(events.active);
    REQUIRE(events.error_events == 0u);
    REQUIRE(events.surface_events >= 3u);
    REQUIRE(trace_capture.surface_rfx_updates == 2u);
    REQUIRE(trace_capture.surface_rfx_tiles == 3u);
    REQUIRE(trace_capture.integrity_failures == 0u);
    REQUIRE(trace_capture.fastpath_integrity_failures == 0u);
    REQUIRE(smoke_rfx_surface_matches(
        librdp_session_get_surface(session)));
    REQUIRE(librdp_session_disconnect(session) ==
            LIBRDP_STATUS_OK);
    REQUIRE(pthread_join(fixture.thread, NULL) == 0);
    thread_started = 0;
    REQUIRE(fixture.status == LIBRDP_STATUS_OK);
    REQUIRE(atomic_load_explicit(&fixture.packet_sent,
                                 memory_order_acquire) == 1u);
    REQUIRE(atomic_load_explicit(&fixture.client_closed,
                                 memory_order_acquire) == 1u);
    result = 0;

cleanup:
    librdp_session_free(session);
    session = NULL;
    if (thread_started)
        (void)pthread_join(fixture.thread, NULL);
    librdp_settings_free(settings);
    return result;
}

/*
 * Verify AVC composition independently of backend-specific rounding. Each
 * codec must replace pixels inside its metadata rectangles, preserve the
 * initialized border outside those rectangles, and leave unmapped desktop
 * pixels untouched.
 */
static int smoke_graphics_avc_surface_matches(
    const librdp_surface* surface)
{
    static const uint8_t background[] = {
        0x11u, 0x22u, 0x33u, 0xffu
    };
    const uint8_t* pixels = NULL;
    size_t stride = 0u;
    unsigned int surface_index = 0u;

    if (!surface ||
        librdp_surface_width(surface) != SMOKE_WIDTH ||
        librdp_surface_height(surface) != SMOKE_HEIGHT)
        return 0;
    pixels = librdp_surface_pixels(surface);
    stride = librdp_surface_stride(surface);
    if (!pixels || stride != (size_t)SMOKE_WIDTH * 4u)
        return 0;

    for (surface_index = 0u;
         surface_index < SMOKE_AVC_SURFACE_COUNT;
         surface_index++)
    {
        unsigned int origin_x =
            (surface_index % SMOKE_AVC_LAYOUT_COLUMNS) *
            (SMOKE_AVC_SURFACE_DIMENSION +
             SMOKE_AVC_LAYOUT_GAP);
        unsigned int origin_y =
            (surface_index / SMOKE_AVC_LAYOUT_COLUMNS) *
            (SMOKE_AVC_SURFACE_DIMENSION +
             SMOKE_AVC_LAYOUT_GAP);
        const uint8_t* inside =
            pixels + ((size_t)(origin_y + 8u) * stride) +
            ((size_t)(origin_x + 8u) * 4u);
        const uint8_t* right_border =
            pixels + ((size_t)(origin_y + 8u) * stride) +
            ((size_t)(origin_x +
                       SMOKE_AVC_SURFACE_DIMENSION - 1u) *
             4u);

        if (inside[3] != 0xffu ||
            CRYPTO_memcmp(inside,
                          background,
                          sizeof(background)) == 0 ||
            CRYPTO_memcmp(right_border,
                          background,
                          sizeof(background)) != 0)
            return 0;
        if ((surface_index & 1u) != 0u)
        {
            const uint8_t* left_border =
                pixels + ((size_t)(origin_y + 8u) * stride) +
                ((size_t)origin_x * 4u);
            const uint8_t* top_border =
                pixels + ((size_t)origin_y * stride) +
                ((size_t)(origin_x + 8u) * 4u);

            if (CRYPTO_memcmp(left_border,
                              background,
                              sizeof(background)) != 0 ||
                CRYPTO_memcmp(top_border,
                              background,
                              sizeof(background)) != 0)
                return 0;
        }
    }

    return pixels[((size_t)(SMOKE_HEIGHT - 1u) * stride) +
                  ((size_t)(SMOKE_WIDTH - 1u) * 4u)] == 0u &&
           pixels[((size_t)(SMOKE_HEIGHT - 1u) * stride) +
                  ((size_t)(SMOKE_WIDTH - 1u) * 4u) + 1u] == 0u &&
           pixels[((size_t)(SMOKE_HEIGHT - 1u) * stride) +
                  ((size_t)(SMOKE_WIDTH - 1u) * 4u) + 2u] == 0u &&
           pixels[((size_t)(SMOKE_HEIGHT - 1u) * stride) +
                  ((size_t)(SMOKE_WIDTH - 1u) * 4u) + 3u] == 0u;
}

/*
 * Model a presenter that cannot acknowledge a completed frame until a bounded
 * presentation interval has elapsed.
 */
static void smoke_slow_graphics_presenter(
    librdp_session* session,
    const librdp_graphics_update* update,
    void* user_data)
{
    smoke_slow_presenter* presenter =
        (smoke_slow_presenter*)user_data;

    (void)session;
    if (!presenter || !update)
        return;
    if (update->type == LIBRDP_GRAPHICS_UPDATE_FRAME_BEGIN)
    {
        presenter->frame_begins++;
    }
    else if (update->type == LIBRDP_GRAPHICS_UPDATE_FRAME_END)
    {
        struct timespec remaining;

        presenter->frame_ends++;
        remaining.tv_sec =
            (time_t)(presenter->delay_ms / 1000u);
        remaining.tv_nsec =
            (long)(presenter->delay_ms % 1000u) * 1000000L;
        while (nanosleep(&remaining, &remaining) != 0 &&
               errno == EINTR)
        {
        }
    }
}

/*
 * Check frame boundaries and every emitted dirty rectangle while the motion
 * workload runs. Black or transparent pixels are impossible in its reference
 * pattern and therefore identify incomplete or uninitialized presentation.
 */
static void smoke_motion_graphics_presenter(
    librdp_session* session,
    const librdp_graphics_update* update,
    void* user_data)
{
    smoke_motion_presenter* presenter =
        (smoke_motion_presenter*)user_data;
    uint32_t y = 0u;
    uint32_t x = 0u;

    (void)session;
    if (!presenter || !update)
        return;
    if (update->type == LIBRDP_GRAPHICS_UPDATE_FRAME_BEGIN)
    {
        if (presenter->active_frame_id != 0u ||
            update->frame_id == 0u)
            presenter->protocol_errors++;
        presenter->active_frame_id = update->frame_id;
        presenter->frame_begins++;
        return;
    }
    if (update->type == LIBRDP_GRAPHICS_UPDATE_FRAME_END)
    {
        if (presenter->active_frame_id == 0u ||
            presenter->active_frame_id != update->frame_id)
            presenter->protocol_errors++;
        presenter->active_frame_id = 0u;
        presenter->frame_ends++;
        return;
    }
    if (update->type != LIBRDP_GRAPHICS_UPDATE_PIXEL_RECT)
        return;
    if (presenter->active_frame_id == 0u)
        return;
    presenter->pixel_rects++;
    if (update->frame_id != presenter->active_frame_id ||
        update->format != LIBRDP_PIXEL_FORMAT_BGRA32 ||
        !update->pixels ||
        update->rect.width == 0u ||
        update->rect.height == 0u ||
        update->rect.x > update->desktop_width ||
        update->rect.y > update->desktop_height ||
        update->rect.width >
            update->desktop_width - update->rect.x ||
        update->rect.height >
            update->desktop_height - update->rect.y ||
        update->stride < (size_t)update->rect.width * 4u)
    {
        presenter->protocol_errors++;
        return;
    }
    for (y = 0u; y < update->rect.height; y++)
    {
        const uint8_t* row =
            update->pixels + (size_t)y * update->stride;

        for (x = 0u; x < update->rect.width; x++)
        {
            const uint8_t* pixel = row + (size_t)x * 4u;

            if ((pixel[0] == 0u &&
                 pixel[1] == 0u &&
                 pixel[2] == 0u) ||
                pixel[3] != 0xffu)
            {
                presenter->protocol_errors++;
                return;
            }
        }
    }
}

/* Keep callback trace identities stable for each graphics fixture. */
static const char* smoke_graphics_trace_id(
    smoke_graphics_mode mode)
{
    switch (mode)
    {
        case SMOKE_GRAPHICS_PLANAR:
            return "graphics-planar";
        case SMOKE_GRAPHICS_PROGRESSIVE:
            return "graphics-progressive";
        case SMOKE_GRAPHICS_LIFECYCLE:
            return "graphics-lifecycle";
        case SMOKE_GRAPHICS_MULTI_SURFACE:
            return "graphics-multi-surface";
        case SMOKE_GRAPHICS_CLEARCODEC:
            return "graphics-clearcodec";
        case SMOKE_GRAPHICS_AVC:
            return "graphics-avc";
        case SMOKE_GRAPHICS_BACKPRESSURE:
            return "graphics-backpressure";
        case SMOKE_GRAPHICS_MOTION:
            return "graphics-motion";
        default:
            return "graphics-unknown";
    }
}

static int smoke_run_graphics(smoke_graphics_mode mode)
{
    static const uint8_t expected_row[] = {
        0x50u, 0x30u, 0x10u, 0xffu,
        0x60u, 0x40u, 0x20u, 0xffu,
        0x70u, 0x80u, 0x90u, 0xffu,
        0xa0u, 0xb0u, 0xc0u, 0xffu
    };
    static const uint8_t expected_multi_row_0[] = {
        0x01u, 0x02u, 0x03u, 0xffu,
        0x04u, 0x05u, 0x06u, 0xffu,
        0x10u, 0x20u, 0x30u, 0xffu,
        0x40u, 0x50u, 0x60u, 0xffu
    };
    static const uint8_t expected_multi_row_1[] = {
        0x07u, 0x08u, 0x09u, 0xffu,
        0x0au, 0x0bu, 0x0cu, 0xffu,
        0x70u, 0x80u, 0x90u, 0xffu,
        0xa0u, 0xb0u, 0xc0u, 0xffu
    };
    static const uint8_t expected_clear_bgr[2][16][3] = {
        {
            {1u, 2u, 3u}, {1u, 2u, 3u},
            {0u, 0u, 0u}, {1u, 2u, 3u},
            {1u, 2u, 3u}, {0u, 0u, 0u},
            {9u, 8u, 7u}, {9u, 8u, 7u},
            {9u, 8u, 7u}, {9u, 8u, 7u},
            {5u, 6u, 7u}, {5u, 6u, 7u},
            {5u, 6u, 7u}, {5u, 6u, 7u},
            {0u, 0u, 0u}, {0u, 0u, 0u}
        },
        {
            {1u, 2u, 3u}, {1u, 2u, 3u},
            {0u, 0u, 0u}, {4u, 5u, 6u},
            {4u, 5u, 6u}, {0u, 0u, 0u},
            {9u, 8u, 7u}, {9u, 8u, 7u},
            {9u, 8u, 7u}, {9u, 8u, 7u},
            {5u, 6u, 7u}, {5u, 6u, 7u},
            {5u, 6u, 7u}, {5u, 6u, 7u},
            {0u, 0u, 0u}, {0u, 0u, 0u}
        }
    };
    smoke_graphics_peer fixture;
    smoke_slow_presenter slow_presenter;
    smoke_motion_presenter motion_presenter;
    smoke_client_events events;
    smoke_trace_capture trace_capture;
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    const librdp_surface* surface = NULL;
    librdp_trace_policy trace_policy;
    librdp_status status = LIBRDP_STATUS_OK;
    uint8_t* expected = NULL;
    uint8_t* motion_background = NULL;
    const uint8_t* pixels = NULL;
    size_t surface_bytes = 0u;
    uint16_t port = 0u;
    unsigned int cycle = 0u;
    unsigned int connection = 0u;
    unsigned int connection_count = 1u;
    unsigned int verified_motion_frames = 0u;
    unsigned int pump_limit =
        mode == SMOKE_GRAPHICS_MOTION
            ? SMOKE_GRAPHICS_MOTION_PUMP_LIMIT
            : SMOKE_PUMP_LIMIT;
    int progressive = mode == SMOKE_GRAPHICS_PROGRESSIVE;
    int reconnect = mode == SMOKE_GRAPHICS_LIFECYCLE;
    int multi_surface = mode == SMOKE_GRAPHICS_MULTI_SURFACE;
    int clearcodec = mode == SMOKE_GRAPHICS_CLEARCODEC;
    int avc = mode == SMOKE_GRAPHICS_AVC;
    int backpressure =
        mode == SMOKE_GRAPHICS_BACKPRESSURE;
    int motion = mode == SMOKE_GRAPHICS_MOTION;
    int thread_started = 0;
    int result = 1;

    REQUIRE(mode >= SMOKE_GRAPHICS_PLANAR &&
            mode <= SMOKE_GRAPHICS_MOTION);
    connection_count = reconnect ? 2u : 1u;
    memset(&fixture, 0, sizeof(fixture));
    memset(&events, 0, sizeof(events));
    memset(&trace_capture, 0, sizeof(trace_capture));
    memset(&slow_presenter, 0, sizeof(slow_presenter));
    memset(&motion_presenter, 0, sizeof(motion_presenter));
    atomic_init(&fixture.port, 0u);
    atomic_init(&fixture.connections, 0u);
    atomic_init(&fixture.caps_advertised, 0u);
    atomic_init(&fixture.frame_acknowledged, 0u);
    atomic_init(&fixture.frame_sent, 0u);
    atomic_init(&fixture.client_closed, 0u);
    fixture.progressive = progressive;
    fixture.reconnect = reconnect;
    fixture.multi_surface = multi_surface;
    fixture.clearcodec = clearcodec;
    fixture.avc = avc;
    fixture.backpressure = backpressure;
    fixture.motion = motion;
    fixture.status = LIBRDP_STATUS_AGAIN;
    REQUIRE(librdp_server_config_init(&fixture.config) ==
            LIBRDP_STATUS_OK);
    fixture.config.bind_address = "127.0.0.1";
    fixture.config.security_mode = LIBRDP_SECURITY_STANDARD;
    fixture.config.width = SMOKE_WIDTH;
    fixture.config.height = SMOKE_HEIGHT;
    REQUIRE(pthread_create(&fixture.thread,
                           NULL,
                           smoke_graphics_peer_main,
                           &fixture) == 0);
    thread_started = 1;
    REQUIRE(smoke_wait_for_port(&fixture.port, &port));

    settings = librdp_settings_new();
    REQUIRE(settings != NULL);
    REQUIRE(librdp_settings_set_target(settings, "127.0.0.1") ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_port(settings, port) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_security_mode(
                settings,
                LIBRDP_SECURITY_STANDARD) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_settings_set_desktop_size(settings,
                                             SMOKE_WIDTH,
                                             SMOKE_HEIGHT) ==
            LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    REQUIRE(session != NULL);
    librdp_session_set_event_callback(session,
                                      smoke_client_event,
                                      &events);
    if (backpressure)
    {
        slow_presenter.delay_ms =
            SMOKE_SLOW_PRESENTER_DELAY_MS;
        librdp_session_set_graphics_update_callback(
            session,
            smoke_slow_graphics_presenter,
            &slow_presenter);
    }
    else if (motion)
    {
        expected = (uint8_t*)malloc(SMOKE_PIXEL_BYTES);
        motion_background =
            (uint8_t*)malloc(SMOKE_PIXEL_BYTES);
        REQUIRE(expected != NULL && motion_background != NULL);
        smoke_graphics_motion_background(motion_background);
        librdp_session_set_graphics_update_callback(
            session,
            smoke_motion_graphics_presenter,
            &motion_presenter);
    }
    REQUIRE(librdp_trace_policy_init(&trace_policy) ==
            LIBRDP_STATUS_OK);
    trace_policy.categories = LIBRDP_TRACE_CATEGORY_ALL;
    trace_policy.level = LIBRDP_TRACE_LEVEL_TRACE;
    trace_policy.sink = LIBRDP_TRACE_SINK_CALLBACK;
    trace_policy.callback = smoke_trace_callback;
    trace_policy.callback_user_data = &trace_capture;
    trace_policy.trace_id = smoke_graphics_trace_id(mode);
    trace_capture.target = "127.0.0.1";
    trace_capture.port = port;
    REQUIRE(librdp_session_set_trace_policy(session,
                                            &trace_policy) ==
            LIBRDP_STATUS_OK);
    REQUIRE(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (connection = 0u;
         connection < connection_count;
         connection++)
    {
        unsigned int required = connection + 1u;
        unsigned int required_frames =
            motion ? required *
                         SMOKE_GRAPHICS_MOTION_FRAME_COUNT
                   : backpressure ? required * 2u : required;
        unsigned int required_surfaces =
            avc ? required * SMOKE_AVC_SURFACE_COUNT
                : multi_surface ? required * 2u : required;

        for (cycle = 0u; cycle < pump_limit; cycle++)
        {
            status = librdp_session_run_once(session, 50);
            REQUIRE(status == LIBRDP_STATUS_OK);
            if (motion &&
                motion_presenter.frame_ends >
                    verified_motion_frames)
            {
                librdp_rect expected_rect;

                REQUIRE(motion_presenter.frame_ends ==
                        verified_motion_frames + 1u);
                surface =
                    librdp_session_get_surface(session);
                REQUIRE(surface != NULL);
                REQUIRE(librdp_surface_width(surface) ==
                        SMOKE_WIDTH);
                REQUIRE(librdp_surface_height(surface) ==
                        SMOKE_HEIGHT);
                REQUIRE(librdp_surface_stride(surface) ==
                        (size_t)SMOKE_WIDTH * 4u);
                smoke_graphics_motion_frame(
                    motion_background,
                    verified_motion_frames,
                    expected,
                    &expected_rect);
                pixels = librdp_surface_pixels(surface);
                REQUIRE(pixels != NULL);
                REQUIRE(CRYPTO_memcmp(pixels,
                                      expected,
                                      SMOKE_PIXEL_BYTES) == 0);
                verified_motion_frames++;
            }
            if (events.active_seen &&
                trace_capture.graphics_caps_confirms >= required &&
                trace_capture.graphics_resets >= required &&
                trace_capture.graphics_surface_creates >= required_surfaces &&
                trace_capture.graphics_surface_maps >= required_surfaces &&
                trace_capture.graphics_frame_starts >= required_frames &&
                trace_capture.graphics_frame_ends >= required_frames &&
                trace_capture.graphics_frame_acks >= required_frames &&
                trace_capture.graphics_surface_deletes >= required_surfaces &&
                ((!progressive && !multi_surface && !clearcodec &&
                  !avc && !motion &&
                  trace_capture.graphics_planar_updates >= required &&
                  trace_capture.graphics_uncompressed_updates >= required) ||
                 (motion &&
                  trace_capture.graphics_uncompressed_updates >=
                      required *
                          SMOKE_GRAPHICS_MOTION_UPDATE_COUNT) ||
                 (multi_surface &&
                  trace_capture.graphics_uncompressed_updates >=
                      required_surfaces) ||
                 (clearcodec &&
                  trace_capture.graphics_clearcodec_updates >=
                      required * 8u) ||
                 (avc &&
                  trace_capture.graphics_avc_support ==
                      RDP_GRAPHICS_AVC_SUPPORT_ALL &&
                  trace_capture.graphics_uncompressed_updates >=
                      required_surfaces &&
                  trace_capture.graphics_avc420_updates >=
                      required * 2u &&
                  trace_capture.graphics_avc444_updates >=
                      required * 3u &&
                  trace_capture.graphics_avc444v2_updates >=
                      required * 3u &&
                  trace_capture.graphics_avc420_decodes >=
                      required * 2u &&
                  trace_capture.graphics_avc444_decodes >=
                      required * 3u &&
                  trace_capture.graphics_avc444v2_decodes >=
                      required * 3u) ||
                 (progressive &&
                  trace_capture.graphics_progressive_first_updates == 2u &&
                  trace_capture.graphics_progressive_upgrade_updates == 3u &&
                  trace_capture.graphics_progressive_missing_tiles == 1u &&
                  trace_capture.graphics_context_deletes == 1u) ||
                 (backpressure &&
                  trace_capture.graphics_progressive_first_updates ==
                      required &&
                  trace_capture.graphics_progressive_upgrade_updates ==
                      required)))
                break;
        }
        REQUIRE(cycle < pump_limit);
        REQUIRE(events.active);
        REQUIRE(events.error_events == 0u);
        surface = librdp_session_get_surface(session);
        REQUIRE(surface != NULL);
        REQUIRE(librdp_surface_width(surface) ==
                ((progressive || backpressure || motion ||
                  multi_surface || clearcodec ||
                  avc) ?
                     SMOKE_WIDTH :
                     SMOKE_WIDTH + 1u));
        REQUIRE(librdp_surface_height(surface) ==
                ((progressive || backpressure || motion ||
                  multi_surface || clearcodec ||
                  avc) ?
                     SMOKE_HEIGHT :
                     SMOKE_HEIGHT + 1u));
        REQUIRE(librdp_surface_stride(surface) ==
                (size_t)((progressive || backpressure || motion ||
                          multi_surface ||
                          clearcodec || avc) ?
                             SMOKE_WIDTH :
                             SMOKE_WIDTH + 1u) *
                    4u);
        surface_bytes = librdp_surface_stride(surface) *
                        librdp_surface_height(surface);
        if (!expected && !avc)
        {
            expected = (uint8_t*)calloc(1u, surface_bytes);
            REQUIRE(expected != NULL);
            if (progressive || backpressure)
            {
                uint32_t y = 0u;
                uint32_t x = 0u;
                size_t stride = librdp_surface_stride(surface);

                for (y = 0u; y < 64u; y++)
                {
                    for (x = 0u; x < 64u; x++)
                    {
                        uint8_t* pixel =
                            expected + ((size_t)y * stride) +
                            ((size_t)x * 4u);

                        pixel[0] = 128u;
                        pixel[1] = 128u;
                        pixel[2] = 128u;
                        pixel[3] = 0xffu;
                    }
                }
            }
            else if (clearcodec)
            {
                size_t y = 0u;
                size_t x = 0u;
                size_t stride = librdp_surface_stride(surface);

                for (y = 0u; y < 2u; y++)
                {
                    for (x = 0u; x < 16u; x++)
                    {
                        uint8_t* pixel =
                            expected + (y * stride) + (x * 4u);

                        pixel[0] = expected_clear_bgr[y][x][0];
                        pixel[1] = expected_clear_bgr[y][x][1];
                        pixel[2] = expected_clear_bgr[y][x][2];
                        pixel[3] = 0xffu;
                    }
                }
            }
            else if (multi_surface)
            {
                memcpy(expected,
                       expected_multi_row_0,
                       sizeof(expected_multi_row_0));
                memcpy(expected + librdp_surface_stride(surface),
                       expected_multi_row_1,
                       sizeof(expected_multi_row_1));
            }
            else
                memcpy(expected, expected_row, sizeof(expected_row));
        }
        pixels = librdp_surface_pixels(surface);
        REQUIRE(pixels != NULL);
        if (avc)
            REQUIRE(smoke_graphics_avc_surface_matches(surface));
        else
            REQUIRE(CRYPTO_memcmp(pixels, expected, surface_bytes) == 0);
        if (connection + 1u < connection_count)
        {
            REQUIRE(librdp_session_reconnect(session, NULL) ==
                    LIBRDP_STATUS_OK);
        }
    }
    REQUIRE(events.surface_events >= 2u * connection_count);
    REQUIRE(librdp_session_disconnect(session) ==
            LIBRDP_STATUS_OK);
    REQUIRE(pthread_join(fixture.thread, NULL) == 0);
    thread_started = 0;
    REQUIRE(fixture.status == LIBRDP_STATUS_OK);
    REQUIRE(atomic_load_explicit(&fixture.connections,
                                 memory_order_acquire) ==
            connection_count);
    REQUIRE(atomic_load_explicit(&fixture.caps_advertised,
                                 memory_order_acquire) ==
            connection_count);
    REQUIRE(atomic_load_explicit(&fixture.frame_acknowledged,
                                 memory_order_acquire) ==
            connection_count *
                (motion
                     ? SMOKE_GRAPHICS_MOTION_FRAME_COUNT
                     : backpressure ? 2u : 1u));
    REQUIRE(atomic_load_explicit(&fixture.frame_sent,
                                 memory_order_acquire) ==
            connection_count);
    REQUIRE(atomic_load_explicit(&fixture.client_closed,
                                 memory_order_acquire) ==
            connection_count);
    REQUIRE(trace_capture.client_connect_successes ==
            connection_count);
    if (motion)
    {
        REQUIRE(verified_motion_frames ==
                SMOKE_GRAPHICS_MOTION_FRAME_COUNT);
        REQUIRE(motion_presenter.frame_begins ==
                SMOKE_GRAPHICS_MOTION_FRAME_COUNT);
        REQUIRE(motion_presenter.frame_ends ==
                SMOKE_GRAPHICS_MOTION_FRAME_COUNT);
        REQUIRE(motion_presenter.pixel_rects ==
                SMOKE_GRAPHICS_MOTION_FRAME_COUNT);
        REQUIRE(motion_presenter.protocol_errors == 0u);
        REQUIRE(fixture.acknowledgement_sequence_errors == 0u);
        REQUIRE(fixture.last_ack_frame_id ==
                SMOKE_GRAPHICS_MOTION_FRAME_COUNT);
        REQUIRE(fixture.last_ack_total_frames ==
                SMOKE_GRAPHICS_MOTION_FRAME_COUNT);
    }
    if (backpressure)
    {
        REQUIRE(fixture.maximum_pending_frames == 1u);
        REQUIRE(fixture.backpressure_rejections == 1u);
        REQUIRE(fixture.acknowledgement_timeouts > 0u);
        REQUIRE(fixture.first_ack_delay_ns >=
                ((uint64_t)SMOKE_SLOW_PRESENTER_DELAY_MS *
                 1000000u) /
                    2u);
        REQUIRE(slow_presenter.frame_begins == 2u);
        REQUIRE(slow_presenter.frame_ends == 2u);
    }
    result = 0;

cleanup:
    free(motion_background);
    free(expected);
    librdp_session_free(session);
    session = NULL;
    if (thread_started)
        (void)pthread_join(fixture.thread, NULL);
    librdp_settings_free(settings);
    return result;
}

static int smoke_parse_security(const char* value,
                                librdp_security_mode* security,
                                librdp_status* expected_status,
                                const smoke_nla_identity** identity,
                                const char** bind_address,
                                const char** target)
{
    if (!value || !security || !expected_status || !identity ||
        !bind_address || !target)
        return 0;
    *expected_status = LIBRDP_STATUS_OK;
    *identity = &smoke_nla_default_identity;
    *bind_address = "127.0.0.1";
    *target = "127.0.0.1";
    if (strcmp(value, "standard") == 0)
        *security = LIBRDP_SECURITY_STANDARD;
    else if (strcmp(value, "standard-dns") == 0)
    {
        *security = LIBRDP_SECURITY_STANDARD;
        *target = "localhost";
    }
    else if (strcmp(value, "standard-ipv6") == 0)
    {
        *security = LIBRDP_SECURITY_STANDARD;
        *bind_address = "::1";
        *target = "::1";
    }
    else if (strcmp(value, "tls") == 0)
        *security = LIBRDP_SECURITY_TLS;
    else if (strcmp(value, "nla") == 0)
        *security = LIBRDP_SECURITY_NLA;
    else if (strcmp(value, "nla-invalid") == 0)
    {
        *security = LIBRDP_SECURITY_NLA;
        *expected_status = LIBRDP_STATUS_AUTHENTICATION_FAILED;
    }
    else if (strcmp(value, "nla-unknown-user") == 0)
    {
        *security = LIBRDP_SECURITY_NLA;
        *expected_status = LIBRDP_STATUS_AUTHENTICATION_FAILED;
        *identity = &smoke_nla_unknown_user_identity;
    }
    else if (strcmp(value, "nla-wrong-domain") == 0)
    {
        *security = LIBRDP_SECURITY_NLA;
        *expected_status = LIBRDP_STATUS_AUTHENTICATION_FAILED;
        *identity = &smoke_nla_wrong_domain_identity;
    }
    else if (strcmp(value, "nla-expired") == 0)
    {
        *security = LIBRDP_SECURITY_NLA;
        *expected_status = LIBRDP_STATUS_CREDENTIALS_EXPIRED;
    }
    else if (strcmp(value, "nla-locked") == 0)
    {
        *security = LIBRDP_SECURITY_NLA;
        *expected_status = LIBRDP_STATUS_ACCOUNT_LOCKED;
    }
    else if (strcmp(value, "nla-no-domain") == 0)
    {
        *security = LIBRDP_SECURITY_NLA;
        *identity = &smoke_nla_no_domain_identity;
    }
    else if (strcmp(value, "nla-empty-domain") == 0)
    {
        *security = LIBRDP_SECURITY_NLA;
        *identity = &smoke_nla_empty_domain_identity;
    }
    else if (strcmp(value, "nla-upn") == 0)
    {
        *security = LIBRDP_SECURITY_NLA;
        *identity = &smoke_nla_upn_identity;
    }
    else if (strcmp(value, "nla-utf8") == 0)
    {
        *security = LIBRDP_SECURITY_NLA;
        *identity = &smoke_nla_utf8_identity;
    }
    else
        return 0;
    return 1;
}

static const smoke_gateway_profile* smoke_gateway_profile_by_name(
    const char* name)
{
    if (!name)
        return NULL;
    if (strcmp(name, "gateway-http-connect") == 0)
        return &smoke_gateway_http_explicit;
    if (strcmp(name, "gateway-session-credentials") == 0)
        return &smoke_gateway_http_session;
    if (strcmp(name, "gateway-no-session-credentials") == 0)
        return &smoke_gateway_http_no_credentials;
    if (strcmp(name, "gateway-auth-failure") == 0)
        return &smoke_gateway_http_auth_failure;
    if (strcmp(name, "gateway-timeout") == 0)
        return &smoke_gateway_http_timeout;
    if (strcmp(name, "gateway-malformed") == 0)
        return &smoke_gateway_http_malformed;
    if (strcmp(name, "gateway-refused") == 0)
        return &smoke_gateway_http_refused;
    if (strcmp(name, "gateway-rdg") == 0)
        return &smoke_gateway_rdg;
    if (strcmp(name, "gateway-rdg-drop-out") == 0)
        return &smoke_gateway_rdg_drop_out;
    if (strcmp(name, "gateway-rdg-drop-in") == 0)
        return &smoke_gateway_rdg_drop_in;
    if (strcmp(name, "gateway-rdg-untrusted") == 0)
        return &smoke_gateway_rdg_untrusted;
    return NULL;
}

static int smoke_viewer_graphics_mode(const char* name,
                                      smoke_graphics_mode* mode)
{
    if (!name || !mode)
        return 0;
    if (strcmp(name, "planar") == 0)
        *mode = SMOKE_GRAPHICS_PLANAR;
    else if (strcmp(name, "progressive") == 0)
        *mode = SMOKE_GRAPHICS_PROGRESSIVE;
    else if (strcmp(name, "multi-surface") == 0)
        *mode = SMOKE_GRAPHICS_MULTI_SURFACE;
    else if (strcmp(name, "clearcodec") == 0)
        *mode = SMOKE_GRAPHICS_CLEARCODEC;
    else if (strcmp(name, "avc") == 0)
        *mode = SMOKE_GRAPHICS_AVC;
    else
        return 0;
    return 1;
}

/*
 * Expose deterministic graphics fixtures to a separately executed viewer.
 * State files are atomically replaced so the supervising X11 test never
 * observes a partial port or frame-ready record.
 */
static int smoke_serve_viewer_graphics(const char* name,
                                       const char* state_path)
{
    smoke_fastpath_peer fastpath;
    smoke_graphics_peer graphics;
    smoke_graphics_mode graphics_mode = SMOKE_GRAPHICS_PLANAR;
    smoke_fastpath_send_fn fastpath_send = NULL;
    atomic_uint* ready = NULL;
    pthread_t* thread = NULL;
    void* (*thread_main)(void*) = NULL;
    void* thread_context = NULL;
    librdp_status* fixture_status = NULL;
    uint16_t port = 0u;
    unsigned int attempt = 0u;

    memset(&fastpath, 0, sizeof(fastpath));
    memset(&graphics, 0, sizeof(graphics));
    if (!name || !state_path)
        return 2;
    if (strcmp(name, "bitmap") == 0)
        fastpath_send = smoke_fastpath_bitmap_send;
    else if (strcmp(name, "nscodec") == 0)
        fastpath_send = smoke_fastpath_nscodec_send;
    else if (strcmp(name, "remotefx") == 0)
        fastpath_send = smoke_fastpath_rfx_send;

    if (fastpath_send)
    {
        atomic_init(&fastpath.port, 0u);
        atomic_init(&fastpath.packet_sent, 0u);
        atomic_init(&fastpath.client_closed, 0u);
        fastpath.send = fastpath_send;
        fastpath.status = LIBRDP_STATUS_AGAIN;
        if (librdp_server_config_init(&fastpath.config) !=
            LIBRDP_STATUS_OK)
            return 1;
        fastpath.config.bind_address = "127.0.0.1";
        fastpath.config.security_mode = LIBRDP_SECURITY_STANDARD;
        fastpath.config.width = SMOKE_WIDTH;
        fastpath.config.height = SMOKE_HEIGHT;
        ready = &fastpath.packet_sent;
        thread = &fastpath.thread;
        thread_main = smoke_fastpath_peer_main;
        thread_context = &fastpath;
        fixture_status = &fastpath.status;
    }
    else
    {
        if (!smoke_viewer_graphics_mode(name, &graphics_mode))
            return 2;
        atomic_init(&graphics.port, 0u);
        atomic_init(&graphics.connections, 0u);
        atomic_init(&graphics.caps_advertised, 0u);
        atomic_init(&graphics.frame_acknowledged, 0u);
        atomic_init(&graphics.frame_sent, 0u);
        atomic_init(&graphics.client_closed, 0u);
        graphics.progressive =
            graphics_mode == SMOKE_GRAPHICS_PROGRESSIVE;
        graphics.multi_surface =
            graphics_mode == SMOKE_GRAPHICS_MULTI_SURFACE;
        graphics.clearcodec =
            graphics_mode == SMOKE_GRAPHICS_CLEARCODEC;
        graphics.avc = graphics_mode == SMOKE_GRAPHICS_AVC;
        graphics.status = LIBRDP_STATUS_AGAIN;
        if (librdp_server_config_init(&graphics.config) !=
            LIBRDP_STATUS_OK)
            return 1;
        graphics.config.bind_address = "127.0.0.1";
        graphics.config.security_mode = LIBRDP_SECURITY_STANDARD;
        graphics.config.width = SMOKE_WIDTH;
        graphics.config.height = SMOKE_HEIGHT;
        ready = &graphics.frame_sent;
        thread = &graphics.thread;
        thread_main = smoke_graphics_peer_main;
        thread_context = &graphics;
        fixture_status = &graphics.status;
    }
    if (pthread_create(thread,
                       NULL,
                       thread_main,
                       thread_context) != 0)
        return 1;
    if (!smoke_wait_for_port(
            fastpath_send ? &fastpath.port : &graphics.port,
            &port) ||
        !test_process_state_write(state_path, port, 0u))
        return 1;
    for (attempt = 0u; attempt < 3000u; attempt++)
    {
        struct timespec delay = {0, 10000000L};

        if (atomic_load_explicit(ready,
                                 memory_order_acquire) > 0u)
            break;
        (void)nanosleep(&delay, NULL);
    }
    if (attempt == 3000u ||
        !test_process_state_write(state_path, port, 1u))
        return 1;
    if (pthread_join(*thread, NULL) != 0)
        return 1;
    return *fixture_status == LIBRDP_STATUS_OK ? 0 : 1;
}

static int smoke_run_clipboard_profile(
    const server_client_clipboard_profile* profile)
{
    if (!profile)
        return 1;
    return smoke_run_profile(LIBRDP_SECURITY_STANDARD,
                             LIBRDP_STATUS_OK,
                             NULL,
                             "127.0.0.1",
                             "127.0.0.1",
                             NULL,
                             0,
                             -1,
                             profile);
}

static int smoke_run_drive_profile(const smoke_drive_profile* profile)
{
    if (!profile)
        return 1;
    return smoke_run_profile_ex(LIBRDP_SECURITY_STANDARD,
                                LIBRDP_STATUS_OK,
                                NULL,
                                "127.0.0.1",
                                "127.0.0.1",
                                NULL,
                                0,
                                -1,
                                NULL,
                                profile,
                                NULL);
}

static int smoke_run_auth_redirection(void)
{
    smoke_auth_redirection auth;

    memset(&auth, 0, sizeof(auth));
    return smoke_run_profile_ex(LIBRDP_SECURITY_NLA,
                                LIBRDP_STATUS_OK,
                                &smoke_nla_default_identity,
                                "127.0.0.1",
                                "127.0.0.1",
                                NULL,
                                0,
                                -1,
                                NULL,
                                NULL,
                                &auth);
}

int main(int argc, char** argv)
{
    librdp_security_mode security = LIBRDP_SECURITY_AUTO;
    librdp_status expected_status = LIBRDP_STATUS_OK;
    const smoke_nla_identity* identity = NULL;
    const smoke_gateway_profile* gateway_profile = NULL;
    const char* bind_address = NULL;
    const char* target = NULL;

    if (argc == 4 &&
        strcmp(argv[1], "viewer-graphics-server") == 0)
        return smoke_serve_viewer_graphics(argv[2], argv[3]);
    if (argc == 2 && strcmp(argv[1], "timeout-credssp") == 0)
        return smoke_run_credssp_timeout();
    if (argc == 2 && strcmp(argv[1], "auth-redirection") == 0)
        return smoke_run_auth_redirection();
    if (argc == 2 && strcmp(argv[1], "standard-integrity") == 0)
        return smoke_run_standard_integrity();
    if (argc == 2 && strcmp(argv[1], "fastpath-bitmap") == 0)
        return smoke_run_fastpath_bitmap();
    if (argc == 2 && strcmp(argv[1], "fastpath-nscodec") == 0)
        return smoke_run_fastpath_nscodec();
    if (argc == 2 && strcmp(argv[1], "fastpath-rfx") == 0)
        return smoke_run_fastpath_rfx();
    if (argc == 2 && strcmp(argv[1], "graphics-planar") == 0)
        return smoke_run_graphics(SMOKE_GRAPHICS_PLANAR);
    if (argc == 2 && strcmp(argv[1], "graphics-progressive") == 0)
        return smoke_run_graphics(SMOKE_GRAPHICS_PROGRESSIVE);
    if (argc == 2 && strcmp(argv[1], "graphics-lifecycle") == 0)
        return smoke_run_graphics(SMOKE_GRAPHICS_LIFECYCLE);
    if (argc == 2 && strcmp(argv[1], "graphics-multi-surface") == 0)
        return smoke_run_graphics(SMOKE_GRAPHICS_MULTI_SURFACE);
    if (argc == 2 && strcmp(argv[1], "graphics-clearcodec") == 0)
        return smoke_run_graphics(SMOKE_GRAPHICS_CLEARCODEC);
    if (argc == 2 && strcmp(argv[1], "graphics-avc") == 0)
        return smoke_run_graphics(SMOKE_GRAPHICS_AVC);
    if (argc == 2 &&
        strcmp(argv[1], "graphics-backpressure") == 0)
        return smoke_run_graphics(SMOKE_GRAPHICS_BACKPRESSURE);
    if (argc == 2 &&
        strcmp(argv[1], "graphics-motion") == 0)
        return smoke_run_graphics(SMOKE_GRAPHICS_MOTION);
    if (argc == 2 && strcmp(argv[1], "security-downgrade") == 0)
        return smoke_run_security_error(
            SMOKE_SECURITY_PEER_DOWNGRADE,
            LIBRDP_STATUS_SECURITY_DOWNGRADE,
            0,
            0);
    if (argc == 2 && strcmp(argv[1], "tls-untrusted") == 0)
        return smoke_run_security_error(
            SMOKE_SECURITY_PEER_TLS_CERTIFICATE,
            LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED,
            0,
            0);
    if (argc == 2 && strcmp(argv[1], "tls-hostname") == 0)
        return smoke_run_security_error(
            SMOKE_SECURITY_PEER_TLS_CERTIFICATE,
            LIBRDP_STATUS_TLS_HOSTNAME_MISMATCH,
            1,
            0);
    if (argc == 2 && strcmp(argv[1], "tls-wrong-pin") == 0)
        return smoke_run_security_error(
            SMOKE_SECURITY_PEER_TLS_CERTIFICATE,
            LIBRDP_STATUS_TLS_CERTIFICATE_REJECTED,
            0,
            1);
    if (argc == 2 && strcmp(argv[1], "tls-handshake") == 0)
        return smoke_run_security_error(
            SMOKE_SECURITY_PEER_TLS_INVALID,
            LIBRDP_STATUS_TLS_HANDSHAKE_FAILED,
            0,
            0);
    if (argc == 2 && strcmp(argv[1], "redirection-standard") == 0)
        return smoke_run_redirection(0, 0);
    if (argc == 2 && strcmp(argv[1], "redirection-tls") == 0)
        return smoke_run_redirection(1, 0);
    if (argc == 2 && strcmp(argv[1], "redirection-loop") == 0)
        return smoke_run_redirection(0, 1);
    if (argc == 2 && strcmp(argv[1], "lifecycle-stress") == 0)
        return smoke_run_lifecycle_stress();
    if (argc == 2 && strcmp(argv[1], "drive-read-only") == 0)
        return smoke_run_drive_profile(&smoke_drive_read_only);
    if (argc == 2 && strcmp(argv[1], "drive-writable") == 0)
        return smoke_run_drive_profile(&smoke_drive_writable);
    if (argc == 2 && strcmp(argv[1], "drive-information") == 0)
        return smoke_run_drive_profile(&smoke_drive_information);
    if (argc == 2 && strcmp(argv[1], "drive-enumeration") == 0)
        return smoke_run_drive_profile(&smoke_drive_enumeration);
    if (argc == 2 && strcmp(argv[1], "drive-locking") == 0)
        return smoke_run_drive_profile(&smoke_drive_locking);
    if (argc == 2 && strcmp(argv[1], "drive-notify") == 0)
        return smoke_run_drive_profile(&smoke_drive_notify);
    if (argc == 2 &&
        strcmp(argv[1], "drive-confinement") == 0)
        return smoke_run_drive_profile(&smoke_drive_confinement);
    if (argc == 2 &&
        strcmp(argv[1], "drive-device-node") == 0)
        return smoke_run_drive_profile(&smoke_drive_device_node);
    if (argc == 2 && strcmp(argv[1], "drive-limits") == 0)
        return smoke_run_drive_profile(&smoke_drive_limits);
    if (argc == 2 && strcmp(argv[1], "drive-metadata") == 0)
    {
#if defined(RDP_HAVE_ATTR) && defined(__linux__)
        return smoke_run_drive_profile(&smoke_drive_metadata);
#else
        return 77;
#endif
    }
    if (argc == 2)
    {
        const server_client_clipboard_profile* clipboard_profile =
            server_client_clipboard_profile_by_name(argv[1]);

        if (clipboard_profile)
            return smoke_run_clipboard_profile(clipboard_profile);
    }
    if (argc == 2 && strcmp(argv[1], "output-control") == 0)
    {
        return smoke_run_profile(LIBRDP_SECURITY_STANDARD,
                                 LIBRDP_STATUS_OK,
                                 NULL,
                                 "127.0.0.1",
                                 "127.0.0.1",
                                 NULL,
                                 1,
                                 -1,
                                 NULL);
    }
    if (argc == 2 &&
        strcmp(argv[1], "cancel-connecting") == 0)
    {
        return smoke_run_profile(LIBRDP_SECURITY_STANDARD,
                                 LIBRDP_STATUS_OK,
                                 NULL,
                                 "127.0.0.1",
                                 "127.0.0.1",
                                 NULL,
                                 0,
                                 LIBRDP_LIFECYCLE_CONNECTING,
                                 NULL);
    }
    if (argc == 2 &&
        strcmp(argv[1], "cancel-negotiating") == 0)
    {
        return smoke_run_profile(LIBRDP_SECURITY_STANDARD,
                                 LIBRDP_STATUS_OK,
                                 NULL,
                                 "127.0.0.1",
                                 "127.0.0.1",
                                 NULL,
                                 0,
                                 LIBRDP_LIFECYCLE_NEGOTIATING,
                                 NULL);
    }
    if (argc == 2 &&
        strcmp(argv[1], "cancel-tls") == 0)
    {
        return smoke_run_profile(LIBRDP_SECURITY_TLS,
                                 LIBRDP_STATUS_OK,
                                 NULL,
                                 "127.0.0.1",
                                 "127.0.0.1",
                                 NULL,
                                 0,
                                 LIBRDP_LIFECYCLE_TLS_HANDSHAKE,
                                 NULL);
    }
    if (argc == 2 &&
        strcmp(argv[1], "cancel-authenticating") == 0)
    {
        return smoke_run_profile(
            LIBRDP_SECURITY_NLA,
            LIBRDP_STATUS_OK,
            &smoke_nla_default_identity,
            "127.0.0.1",
            "127.0.0.1",
            NULL,
            0,
            LIBRDP_LIFECYCLE_AUTHENTICATING,
            NULL);
    }
    if (argc == 2 &&
        strcmp(argv[1], "cancel-activating") == 0)
    {
        return smoke_run_profile(LIBRDP_SECURITY_STANDARD,
                                 LIBRDP_STATUS_OK,
                                 NULL,
                                 "127.0.0.1",
                                 "127.0.0.1",
                                 NULL,
                                 0,
                                 LIBRDP_LIFECYCLE_ACTIVATING,
                                 NULL);
    }
    if (argc == 2)
        gateway_profile =
            smoke_gateway_profile_by_name(argv[1]);
    if (gateway_profile)
    {
#ifdef RDP_HAVE_CURL
        return smoke_run_profile(
            LIBRDP_SECURITY_NLA,
            LIBRDP_STATUS_OK,
            &smoke_nla_default_identity,
            "127.0.0.1",
            "127.0.0.1",
            gateway_profile,
            0,
            -1,
            NULL);
#else
        return 77;
#endif
    }
    if (argc != 2 ||
        !smoke_parse_security(argv[1],
                              &security,
                              &expected_status,
                              &identity,
                              &bind_address,
                              &target))
    {
        fprintf(stderr,
                "usage: test_server_client_smoke "
                "standard|standard-dns|standard-ipv6|tls|nla|"
                "nla-invalid|nla-unknown-user|nla-wrong-domain|"
                "nla-expired|nla-locked|"
                "nla-no-domain|nla-empty-domain|nla-upn|nla-utf8|"
                "timeout-credssp|auth-redirection|standard-integrity|fastpath-bitmap|"
                "fastpath-nscodec|fastpath-rfx|"
                "graphics-planar|graphics-progressive|"
                "graphics-lifecycle|graphics-multi-surface|"
                "graphics-clearcodec|graphics-avc|"
                "graphics-backpressure|"
                "graphics-motion|"
                "security-downgrade|"
                "tls-untrusted|tls-hostname|tls-wrong-pin|tls-handshake|"
                "redirection-standard|redirection-tls|redirection-loop|"
                "lifecycle-stress|drive-read-only|drive-writable|"
                "drive-information|drive-enumeration|drive-locking|"
                "drive-notify|drive-metadata|drive-confinement|"
                "drive-device-node|drive-limits|"
                "clipboard-text|clipboard-html|"
                "clipboard-png|output-control|"
                "cancel-connecting|cancel-negotiating|"
                "cancel-tls|cancel-authenticating|cancel-activating|"
                "gateway-http-connect|gateway-session-credentials|"
                "gateway-no-session-credentials|gateway-auth-failure|"
                "gateway-timeout|gateway-malformed|gateway-refused|"
                "gateway-rdg|gateway-rdg-drop-out|gateway-rdg-drop-in|"
                "gateway-rdg-untrusted|"
                "viewer-graphics-server fixture state-file\n");
        return 2;
    }
    return smoke_run_profile(security,
                             expected_status,
                             identity,
                             bind_address,
                             target,
                             NULL,
                             0,
                             -1,
                             NULL);
}
