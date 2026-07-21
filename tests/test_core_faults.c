/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: deterministic allocation-failure smoke tests.
 * Coverage: settings clone, connection setup, DVC open, decoder construction,
 * and worker-backed printer startup ownership boundaries.
 * Bug classes: partial state commits, leaked allocations, stale handles,
 * missing public errors, and failed retry after transient memory pressure.
 * Determinism: internal one-shot fault points avoid host overcommit behavior.
 */

#include "test_core_support.h"
#include "test_core_suites.h"

#include "client/printer_backend.h"
#include "client/session_internal.h"
#include "common/fault_injection.h"
#include "graphics/avc.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int test_start_closing_peer(uint16_t* port, pid_t* child)
{
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    int listener = -1;

    if (!port || !child)
        return 0;
    *port = 0u;
    *child = -1;
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0)
        return 0;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(listener, (const struct sockaddr*)&address, sizeof(address)) != 0 ||
        getsockname(listener, (struct sockaddr*)&address, &address_len) != 0 ||
        listen(listener, 1) != 0)
    {
        close(listener);
        return 0;
    }
    *port = ntohs(address.sin_port);
    *child = fork();
    if (*child < 0)
    {
        close(listener);
        return 0;
    }
    if (*child == 0)
    {
        int client = accept(listener, NULL, NULL);

        if (client >= 0)
            close(client);
        close(listener);
        _exit(client >= 0 ? 0 : 1);
    }
    close(listener);
    return 1;
}

/*
 * A failed clone must destroy its partial destination while preserving every
 * owned field in the source. The one-shot point then permits an exact retry.
 */
static int test_settings_clone_allocation_failure(void)
{
    librdp_settings* settings = NULL;
    librdp_settings* clone = NULL;

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "test.invalid") ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_username(settings, "allocation-user") ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_password(settings, "ephemeral-secret") ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_settings_add_drive(settings, "DATA", "/tmp") ==
          LIBRDP_STATUS_OK);

    rdp_fault_injection_arm(RDP_FAULT_SETTINGS_CLONE, 0u);
    CHECK(librdp_settings_clone(settings) == NULL);
    clone = librdp_settings_clone(settings);
    CHECK(clone != NULL);
    CHECK(strcmp(librdp_settings_target(clone), "test.invalid") == 0);
    CHECK(strcmp(librdp_settings_username(clone), "allocation-user") == 0);
    CHECK(librdp_settings_drive_count(clone) == 1u);

    librdp_settings_free(clone);
    librdp_settings_free(settings);
    return 0;
}

/*
 * Connection setup memory pressure remains pre-commit and records a public
 * error. A retry reaches the transport and fails only when the controlled peer
 * closes, proving the allocation point was consumed.
 */
static int test_connect_allocation_failure(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_error_info error;
    uint16_t port = 0u;
    pid_t child = -1;
    int child_status = 0;
    librdp_status status = LIBRDP_STATUS_OK;

    CHECK(test_start_closing_peer(&port, &child));
    settings = librdp_settings_new();
    CHECK(settings != NULL);
    CHECK(librdp_settings_set_target(settings, "127.0.0.1") ==
          LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_port(settings, port) == LIBRDP_STATUS_OK);
    CHECK(librdp_settings_set_security_mode(
              settings, LIBRDP_SECURITY_STANDARD) == LIBRDP_STATUS_OK);
    session = librdp_session_new(settings);
    CHECK(session != NULL);

    rdp_fault_injection_arm(RDP_FAULT_CONNECT_ALLOCATION, 0u);
    CHECK(librdp_session_connect(session) == LIBRDP_STATUS_NO_MEMORY);
    CHECK(librdp_session_get_state(session) == LIBRDP_SESSION_FAILED);
    CHECK(librdp_error_info_init(&error) == LIBRDP_STATUS_OK);
    CHECK(librdp_error_copy_info(librdp_session_last_error(session), &error) ==
          LIBRDP_STATUS_OK);
    CHECK(error.status == LIBRDP_STATUS_NO_MEMORY);
    CHECK(error.component == LIBRDP_ERROR_COMPONENT_CLIENT);
    CHECK(error.phase && strcmp(error.phase, "client.connect.allocate") == 0);

    status = librdp_session_connect(session);
    CHECK(status != LIBRDP_STATUS_OK && status != LIBRDP_STATUS_NO_MEMORY);
    CHECK(waitpid(child, &child_status, 0) == child);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);

    librdp_session_free(session);
    librdp_settings_free(settings);
    return 0;
}

/*
 * DVC allocation failure leaves both the caller handle and the session channel
 * table empty. The retry writes a valid create request over a local socket.
 */
static int test_channel_open_allocation_failure(void)
{
    librdp_settings* settings = NULL;
    librdp_session* session = NULL;
    librdp_channel_handle handle = 0u;
    librdp_channel_info info;
    size_t channel_count = 0u;
    int sockets[2] = {-1, -1};

    settings = librdp_settings_new();
    CHECK(settings != NULL);
    session = librdp_session_new(settings);
    CHECK(session != NULL);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    rdp_transport_attach_fd(&session->transport, sockets[0], 1);
    sockets[0] = -1;
    session->state = LIBRDP_SESSION_CONNECTED;
    session->mcs_user_id = 1001u;
    session->dynamic_channel_id = 1004u;

    rdp_fault_injection_arm(RDP_FAULT_CHANNEL_OPEN_ALLOCATION, 0u);
    CHECK(librdp_session_channel_open(session,
                                      "allocation.test",
                                      LIBRDP_CHANNEL_PRIORITY_LOW,
                                      &handle) == LIBRDP_STATUS_NO_MEMORY);
    CHECK(handle == 0u);
    CHECK(librdp_session_channel_list(session, NULL, 0u, &channel_count) ==
          LIBRDP_STATUS_OK);
    CHECK(channel_count == 0u);

    CHECK(librdp_session_channel_open(session,
                                      "allocation.test",
                                      LIBRDP_CHANNEL_PRIORITY_LOW,
                                      &handle) == LIBRDP_STATUS_OK);
    CHECK(handle != 0u);
    CHECK(librdp_channel_info_init(&info) == LIBRDP_STATUS_OK);
    CHECK(librdp_session_channel_get_info(session, handle, &info) ==
          LIBRDP_STATUS_OK);
    CHECK(!info.active && info.application_owned);
    CHECK(librdp_session_channel_list(session, NULL, 0u, &channel_count) ==
          LIBRDP_STATUS_OK);
    CHECK(channel_count == 0u);

    session->state = LIBRDP_SESSION_IDLE;
    librdp_session_free(session);
    CHECK(close(sockets[1]) == 0);
    librdp_settings_free(settings);
    return 0;
}

/* Decoder and backend construction must remain retryable after exact failures. */
static int test_decoder_backend_allocation_failures(void)
{
    rdp_avc_decoder* decoder = NULL;
    rdp_printer_backend backend;
    rdp_printer_backend_mock mock;

    rdp_fault_injection_arm(RDP_FAULT_DECODER_ALLOCATION, 0u);
    CHECK(rdp_avc_decoder_new() == NULL);
    decoder = rdp_avc_decoder_new();
    CHECK(decoder != NULL);
    rdp_avc_decoder_free(decoder);

    rdp_printer_backend_mock_init(&mock);
    rdp_fault_injection_arm(RDP_FAULT_BACKEND_STARTUP, 0u);
    rdp_printer_backend_init_mock(&backend, &mock);
    CHECK(backend.runtime == NULL);
    rdp_printer_backend_clear(&backend);
    rdp_printer_backend_init_mock(&backend, &mock);
    CHECK(backend.runtime != NULL);
    rdp_printer_backend_clear(&backend);
    return 0;
}

int test_allocation_failure_boundaries(void)
{
    int status = 0;

    rdp_fault_injection_reset();
    if (test_settings_clone_allocation_failure() != 0 ||
        test_connect_allocation_failure() != 0 ||
        test_channel_open_allocation_failure() != 0 ||
        test_decoder_backend_allocation_failures() != 0)
        status = 1;
    rdp_fault_injection_reset();
    return status;
}
