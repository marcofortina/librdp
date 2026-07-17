/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: client storage tests.
 * Coverage: filesystem information classes and printer backend lifecycle.
 * Bug classes: malformed input, invalid state, bounds, ownership, and cleanup.
 * Determinism: fixtures use synthetic data and local transports only.
 */

#include "test_core_support.h"
#include "test_core_suites.h"

/*
 * Fixture: drives a printer file-backend job over RDPDR using the same parser
 * and writer functions as protocol tests. It covers create/write/read/query,
 * flush, close, and a post-close write rejection without requiring a print
 * system daemon.
 */
int run_printer_job_server_scenario(int fd, uint8_t* input, size_t capacity)
{
    static const uint8_t create_path[] = {0, 0};
    static const uint8_t document[] = {'p', 'r', 'i', 'n', 't', '-', 'j', 'o', 'b', '\n'};
    static const uint8_t query_buffer[64] = {0};
    enum
    {
        device_channel_id = 1006,
        completion_create = 0x100u,
        completion_write = 0x101u,
        completion_read = 0x102u,
        completion_query = 0x103u,
        completion_flush = 0x104u,
        completion_close = 0x105u,
        completion_write_after_close = 0x106u,
        file_standard_information = 5u
    };
    rdp_buffer server_announce;
    rdp_buffer server_caps;
    rdp_buffer user_loggedon;
    rdp_buffer request;
    rdp_buffer device_reply;
    uint32_t device_id = 0;
    uint32_t file_id = 0;
    int ok = 0;

    rdp_buffer_init(&server_announce);
    rdp_buffer_init(&server_caps);
    rdp_buffer_init(&user_loggedon);
    rdp_buffer_init(&request);
    rdp_buffer_init(&device_reply);

    ok = rdp_device_redirection_write_server_announce(&server_announce,
                                                      RDP_DEVICE_REDIRECTION_VERSION_MINOR_13,
                                                      0x11223344u) == LIBRDP_STATUS_OK &&
         write_device_static_packet_fd(fd, &server_announce, device_channel_id) &&
         read_client_device_announce_fd(fd, input, capacity, device_channel_id) &&
         read_client_device_name_fd(fd, input, capacity, device_channel_id) &&
         build_device_redirection_server_capabilities(&server_caps) &&
         write_device_static_packet_fd(fd, &server_caps, device_channel_id) &&
         read_client_device_capabilities_fd(fd, input, capacity, device_channel_id) &&
         rdp_device_redirection_write_user_loggedon(&user_loggedon) == LIBRDP_STATUS_OK &&
         write_device_static_packet_fd(fd, &user_loggedon, device_channel_id) &&
         read_client_printer_device_id_fd(fd, input, capacity, device_channel_id, &device_id) &&
         rdp_device_redirection_write_device_reply(&device_reply,
                                                   device_id,
                                                   RDP_DEVICE_REDIRECTION_STATUS_SUCCESS) == LIBRDP_STATUS_OK &&
         write_device_static_packet_fd(fd, &device_reply, device_channel_id);
    if (!ok)
        goto done;

    request.length = 0;
    ok = rdp_filesystem_redirection_write_create_request(&request,
                                                         device_id,
                                                         0,
                                                         completion_create,
                                                         0,
                                                         0,
                                                         0,
                                                         0,
                                                         1,
                                                         0,
                                                         create_path,
                                                         (uint32_t)sizeof(create_path)) == LIBRDP_STATUS_OK &&
         write_device_static_packet_fd(fd, &request, device_channel_id) &&
         read_client_printer_create_response_fd(fd,
                                                input,
                                                capacity,
                                                device_channel_id,
                                                device_id,
                                                completion_create,
                                                &file_id);
    if (!ok)
        goto done;

    request.length = 0;
    ok = rdp_filesystem_redirection_write_write_request(&request,
                                                        device_id,
                                                        file_id,
                                                        completion_write,
                                                        0,
                                                        document,
                                                        (uint32_t)sizeof(document)) == LIBRDP_STATUS_OK &&
         write_device_static_packet_fd(fd, &request, device_channel_id) &&
         read_client_printer_write_response_fd(fd,
                                               input,
                                               capacity,
                                               device_channel_id,
                                               device_id,
                                               completion_write,
                                               (uint32_t)sizeof(document),
                                               1);
    if (!ok)
        goto done;

    request.length = 0;
    ok = rdp_filesystem_redirection_write_read_request(&request,
                                                       device_id,
                                                       file_id,
                                                       completion_read,
                                                       (uint32_t)sizeof(document),
                                                       0) == LIBRDP_STATUS_OK &&
         write_device_static_packet_fd(fd, &request, device_channel_id) &&
         read_client_printer_read_response_fd(fd,
                                              input,
                                              capacity,
                                              device_channel_id,
                                              device_id,
                                              completion_read,
                                              document,
                                              (uint32_t)sizeof(document));
    if (!ok)
        goto done;

    request.length = 0;
    ok = rdp_filesystem_redirection_write_information_request(&request,
                                                              device_id,
                                                              file_id,
                                                              completion_query,
                                                              RDP_DEVICE_REDIRECTION_IRP_QUERY_INFORMATION,
                                                              file_standard_information,
                                                              query_buffer,
                                                              (uint32_t)sizeof(query_buffer)) == LIBRDP_STATUS_OK &&
         write_device_static_packet_fd(fd, &request, device_channel_id) &&
         read_client_printer_query_response_fd(fd,
                                               input,
                                               capacity,
                                               device_channel_id,
                                               device_id,
                                               completion_query);
    if (!ok)
        goto done;

    request.length = 0;
    ok = rdp_device_redirection_write_io_request(&request,
                                                 device_id,
                                                 file_id,
                                                 completion_flush,
                                                 RDP_DEVICE_REDIRECTION_IRP_FLUSH_BUFFERS,
                                                 0,
                                                 NULL,
                                                 0) == LIBRDP_STATUS_OK &&
         write_device_static_packet_fd(fd, &request, device_channel_id) &&
         read_client_device_completion_fd(fd,
                                          input,
                                          capacity,
                                          device_channel_id,
                                          device_id,
                                          completion_flush);
    if (!ok)
        goto done;

    request.length = 0;
    ok = rdp_filesystem_redirection_write_close_request(&request,
                                                        device_id,
                                                        file_id,
                                                        completion_close) == LIBRDP_STATUS_OK &&
         write_device_static_packet_fd(fd, &request, device_channel_id) &&
         read_client_printer_close_response_fd(fd,
                                               input,
                                               capacity,
                                               device_channel_id,
                                               device_id,
                                               completion_close);
    if (!ok)
        goto done;

    request.length = 0;
    ok = rdp_filesystem_redirection_write_write_request(&request,
                                                        device_id,
                                                        file_id,
                                                        completion_write_after_close,
                                                        0,
                                                        document,
                                                        (uint32_t)sizeof(document)) == LIBRDP_STATUS_OK &&
         write_device_static_packet_fd(fd, &request, device_channel_id) &&
         read_client_printer_write_response_fd(fd,
                                               input,
                                               capacity,
                                               device_channel_id,
                                               device_id,
                                               completion_write_after_close,
                                               0,
                                               0);

done:
    rdp_buffer_free(&device_reply);
    rdp_buffer_free(&request);
    rdp_buffer_free(&user_loggedon);
    rdp_buffer_free(&server_caps);
    rdp_buffer_free(&server_announce);
    return ok;
}

/*
 * Coverage: validates printer redirection against a real file-backed spool
 * job. The mock server drives RDPDR negotiation and IRPs, while the client
 * creates, writes, reads, queries, flushes, closes, and rejects stale writes
 * for a redirected printer without relying on CUPS.
 */
int test_printer_file_backend_job_lifecycle(void)
{
    static const uint8_t expected[] = {'p', 'r', 'i', 'n', 't', '-', 'j', 'o', 'b', '\n'};
    char output_dir[] = "/tmp/librdp-printer-XXXXXX";
    char output_path[512];
    uint8_t actual[sizeof(expected)];
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    uint16_t test_port = 0;
    pid_t server_pid = -1;
    int child_status = 0;
    int output_fd = -1;
    int needed = 0;
    char extra = 0;
    pid_t wait_rc = 0;

    CHECK(mkdtemp(output_dir) != NULL);
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_printer(settings, "Print", "Generic", output_dir) == LIBRDP_STATUS_OK);
    CHECK(start_handshake_server_multi(&test_port,
                                       &server_pid,
                                       0,
                                       0,
                                       1,
                                       0,
                                       1,
                                       DVC_SCENARIO_RDPDR_PRINTER_JOB,
                                       0,
                                       CLIPBOARD_SCENARIO_NONE));
    CHECK(librdp_settings_set_port(settings, test_port) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_OK);
    for (size_t i = 0; i < 32u && server_pid > 0; i++)
    {
        librdp_status status = librdp_session_run_once(session, 1000);

        wait_rc = waitpid(server_pid, &child_status, WNOHANG);
        if (wait_rc == server_pid)
        {
            CHECK(i >= 13u);
            server_pid = -1;
            break;
        }
        CHECK(wait_rc == 0);
        if (status != LIBRDP_STATUS_OK &&
            i >= 13u &&
            librdp_session_get_state(session) != LIBRDP_SESSION_FAILED)
        {
            break;
        }
        CHECK(status == LIBRDP_STATUS_OK);
    }

    librdp_session_free(session);
    session = NULL;
    librdp_settings_free(settings);
    settings = NULL;
    if (server_pid > 0)
    {
        CHECK(waitpid(server_pid, &child_status, 0) == server_pid);
        server_pid = -1;
    }
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);

    needed = snprintf(output_path, sizeof(output_path), "%s/Print-%08x.prn", output_dir, 1u);
    CHECK(needed > 0 && (size_t)needed < sizeof(output_path));
    output_fd = open(output_path, O_RDONLY);
    CHECK(output_fd >= 0);
    CHECK(read_exact_fd(output_fd, actual, sizeof(actual)));
    CHECK(read(output_fd, &extra, sizeof(extra)) == 0);
    CHECK(close(output_fd) == 0);
    output_fd = -1;
    CHECK(memcmp(actual, expected, sizeof(expected)) == 0);
    CHECK(unlink(output_path) == 0);
    CHECK(rmdir(output_dir) == 0);
    return 0;
}

/*
 * Coverage: verifies RDPEFS file and directory information-class coverage
 * without a remote server. The fixture checks that supported query layouts are
 * serialized, modern directory ID classes are present, and usage mismatches fail
 * as invalid parameters instead of looking like missing backend support.
 */
int test_filesystem_information_class_coverage(void)
{
    static const uint32_t query_classes[] = {
        RDP_SESSION_FILE_BASIC_INFORMATION,
        RDP_SESSION_FILE_STANDARD_INFORMATION,
        RDP_SESSION_FILE_INTERNAL_INFORMATION,
        RDP_SESSION_FILE_EA_INFORMATION,
        RDP_SESSION_FILE_ACCESS_INFORMATION,
        RDP_SESSION_FILE_NAME_INFORMATION,
        RDP_SESSION_FILE_NORMALIZED_NAME_INFORMATION,
        RDP_SESSION_FILE_FULL_EA_INFORMATION,
        RDP_SESSION_FILE_POSITION_INFORMATION,
        RDP_SESSION_FILE_MODE_INFORMATION,
        RDP_SESSION_FILE_ALIGNMENT_INFORMATION,
        RDP_SESSION_FILE_ALL_INFORMATION,
        RDP_SESSION_FILE_ALTERNATE_NAME_INFORMATION,
        RDP_SESSION_FILE_STREAM_INFORMATION,
        RDP_SESSION_FILE_COMPRESSION_INFORMATION,
        RDP_SESSION_FILE_NETWORK_OPEN_INFORMATION,
        RDP_SESSION_FILE_ATTRIBUTE_TAG_INFORMATION,
        RDP_SESSION_FILE_ID_INFORMATION,
        RDP_SESSION_FILE_CASE_SENSITIVE_INFORMATION,
        RDP_SESSION_FILE_ALLOCATION_INFORMATION,
        RDP_SESSION_FILE_END_OF_FILE_INFORMATION,
        RDP_SESSION_FILE_VALID_DATA_LENGTH_INFORMATION};
    static const uint32_t invalid_file_query_classes[] = {
        RDP_SESSION_FILE_DIRECTORY_INFORMATION,
        RDP_SESSION_FILE_FULL_DIRECTORY_INFORMATION,
        RDP_SESSION_FILE_BOTH_DIRECTORY_INFORMATION,
        RDP_SESSION_FILE_NAMES_INFORMATION,
        RDP_SESSION_FILE_ID_BOTH_DIRECTORY_INFORMATION,
        RDP_SESSION_FILE_ID_FULL_DIRECTORY_INFORMATION,
        RDP_SESSION_FILE_ID_EXTD_DIRECTORY_INFORMATION,
        RDP_SESSION_FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION,
        RDP_SESSION_FILE_ID_64_EXTD_DIRECTORY_INFORMATION,
        RDP_SESSION_FILE_ID_64_EXTD_BOTH_DIRECTORY_INFORMATION,
        RDP_SESSION_FILE_ID_ALL_EXTD_DIRECTORY_INFORMATION,
        RDP_SESSION_FILE_ID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION,
        RDP_SESSION_FILE_RENAME_INFORMATION,
        RDP_SESSION_FILE_LINK_INFORMATION,
        RDP_SESSION_FILE_DISPOSITION_INFORMATION,
        RDP_SESSION_FILE_DISPOSITION_INFORMATION_EX,
        RDP_SESSION_FILE_RENAME_INFORMATION_EX,
        RDP_SESSION_FILE_LINK_INFORMATION_EX,
        RDP_SESSION_FILE_PIPE_INFORMATION,
        RDP_SESSION_FILE_PIPE_LOCAL_INFORMATION,
        RDP_SESSION_FILE_PIPE_REMOTE_INFORMATION,
        RDP_SESSION_FILE_MAILSLOT_QUERY_INFORMATION,
        RDP_SESSION_FILE_MAILSLOT_SET_INFORMATION,
        RDP_SESSION_FILE_OBJECT_ID_INFORMATION,
        RDP_SESSION_FILE_MOVE_CLUSTER_INFORMATION,
        RDP_SESSION_FILE_QUOTA_INFORMATION,
        RDP_SESSION_FILE_REPARSE_POINT_INFORMATION,
        RDP_SESSION_FILE_TRACKING_INFORMATION,
        RDP_SESSION_FILE_SHORT_NAME_INFORMATION,
        RDP_SESSION_FILE_SFIO_RESERVE_INFORMATION,
        RDP_SESSION_FILE_SFIO_VOLUME_INFORMATION,
        RDP_SESSION_FILE_HARD_LINK_INFORMATION,
        RDP_SESSION_FILE_ID_GLOBAL_TX_DIRECTORY_INFORMATION,
        RDP_SESSION_FILE_STANDARD_LINK_INFORMATION};
    static const struct
    {
        uint32_t information_class;
        size_t fixed_size;
    } directory_classes[] = {
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
        {RDP_SESSION_FILE_ID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION, 122u}};
    const char* directory_name = "sample.txt";
    char path[] = "/tmp/librdp-rdpefs-info-XXXXXX";
    rdp_session_redirected_file file;
    rdp_buffer buffer;
    struct stat st;
    int fd = -1;
    size_t i = 0;
    size_t utf16_name_len = strlen(directory_name) * 2u;

    memset(&file, 0, sizeof(file));
    memset(&st, 0, sizeof(st));
    rdp_buffer_init(&buffer);
    fd = mkstemp(path);
    CHECK(fd >= 0);
    CHECK(write(fd, "abcdef", 6u) == 6);
    CHECK(fstat(fd, &st) == 0);
    file.active = 1;
    file.fd = fd;
    file.path = path;
    file.desired_access = 0x0012019fu;
    file.create_options = 0x00000020u;
    file.delete_pending = 1;

    for (i = 0; i < sizeof(query_classes) / sizeof(query_classes[0]); i++)
    {
        rdp_buffer_free(&buffer);
        rdp_buffer_init(&buffer);
        CHECK(rdp_session_write_file_information(&buffer, query_classes[i], &st, &file) == LIBRDP_STATUS_OK);
        CHECK(buffer.length >= 4u || query_classes[i] == RDP_SESSION_FILE_FULL_EA_INFORMATION);
    }
    for (i = 0; i < sizeof(invalid_file_query_classes) / sizeof(invalid_file_query_classes[0]); i++)
    {
        rdp_buffer_free(&buffer);
        rdp_buffer_init(&buffer);
        CHECK(rdp_session_write_file_information(&buffer,
                                                 invalid_file_query_classes[i],
                                                 &st,
                                                 &file) == LIBRDP_STATUS_INVALID_ARGUMENT);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    CHECK(rdp_session_write_file_information(&buffer, 0xffffffffu, &st, &file) == LIBRDP_STATUS_INVALID_ARGUMENT);

    for (i = 0; i < sizeof(directory_classes) / sizeof(directory_classes[0]); i++)
    {
        rdp_buffer_free(&buffer);
        rdp_buffer_init(&buffer);
        CHECK(rdp_session_write_directory_information(&buffer,
                                                      directory_classes[i].information_class,
                                                      &st,
                                                      directory_name) == LIBRDP_STATUS_OK);
        CHECK(buffer.length == directory_classes[i].fixed_size + utf16_name_len);
    }
    rdp_buffer_free(&buffer);
    rdp_buffer_init(&buffer);
    CHECK(rdp_session_write_directory_information(&buffer,
                                                  RDP_SESSION_FILE_BASIC_INFORMATION,
                                                  &st,
                                                  directory_name) == LIBRDP_STATUS_INVALID_ARGUMENT);
    CHECK(rdp_session_write_directory_information(&buffer,
                                                  0xffffffffu,
                                                  &st,
                                                  directory_name) == LIBRDP_STATUS_INVALID_ARGUMENT);
    rdp_buffer_free(&buffer);
    CHECK(close(fd) == 0);
    fd = -1;
    CHECK(unlink(path) == 0);
    return 0;
}
