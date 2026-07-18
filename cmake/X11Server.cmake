# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_X11_SERVER)
    if(NOT UNIX OR APPLE)
        message(FATAL_ERROR "LIBRDP_BUILD_X11_SERVER requires an X11 Unix platform")
    endif()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBRDP_X11_SERVER REQUIRED IMPORTED_TARGET
        x11
        xdamage
        xcomposite
        xtst
        xfixes
        xrandr
        xkbcommon
        xau
    )
    if(NOT "${LIBRDP_WITH_XSHM}" STREQUAL "OFF")
        pkg_check_modules(LIBRDP_X11_SERVER_XEXT QUIET IMPORTED_TARGET xext)
        if(LIBRDP_X11_SERVER_XEXT_FOUND)
            set(LIBRDP_X11_SERVER_XSHM_FOUND 1 CACHE INTERNAL
                "MIT-SHM support found for the X11 server" FORCE)
        elseif("${LIBRDP_WITH_XSHM}" STREQUAL "ON")
            message(FATAL_ERROR "LIBRDP_WITH_XSHM=ON requires Xext")
        endif()
    endif()

    set(LIBRDP_X11_SERVER_PLATFORM_SOURCES
        apps/x11/x11_keymap.c
        apps/x11/server/server_capture.c
        apps/x11/server/server_clipboard.c
        apps/x11/server/server_input.c
        apps/x11/server/server_permission.c
        apps/x11/server/server_pointer.c
        apps/common/server_fuse.c
        apps/x11/server/server_runtime.c
        apps/x11/server/server_x11.c
    )

    function(librdp_configure_x11_server_target target)
        target_include_directories(${target} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(${target} PRIVATE
            librdp_app_common
            Iconv::Iconv
            OpenSSL::Crypto
            PkgConfig::LIBRDP_X11_SERVER
            Threads::Threads
        )
        if(LIBRDP_FUSE3_FOUND)
            target_compile_definitions(${target} PRIVATE
                LIBRDP_HAVE_FUSE3=1
            )
            target_link_libraries(${target} PRIVATE
                PkgConfig::LIBRDP_FUSE3
            )
        endif()
        if(LIBRDP_X11_SERVER_XSHM_FOUND)
            target_compile_definitions(${target} PRIVATE
                LIBRDP_HAVE_XSHM=1
            )
            target_link_libraries(${target} PRIVATE
                PkgConfig::LIBRDP_X11_SERVER_XEXT
            )
        endif()
        librdp_apply_system_definitions(${target})
        librdp_apply_warning_options(${target})
        librdp_apply_sanitizer_compile_options(${target})
        librdp_apply_sanitizer_link_options(${target})
    endfunction()

    function(librdp_configure_x11_managed_target target)
        target_include_directories(${target} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(${target} PRIVATE
            librdp
            OpenSSL::Crypto
            Threads::Threads
        )
        target_compile_definitions(${target} PRIVATE
            LIBRDP_X11_SESSION_SUPERVISOR_PATH="${CMAKE_INSTALL_FULL_BINDIR}/librdp-x11-session-supervisor"
            LIBRDP_X11_SESSION_AGENT_PATH="${CMAKE_INSTALL_FULL_BINDIR}/librdp-x11-session-agent"
        )
        librdp_apply_system_definitions(${target})
        librdp_apply_warning_options(${target})
        librdp_apply_sanitizer_compile_options(${target})
        librdp_apply_sanitizer_link_options(${target})
    endfunction()

    add_executable(librdp-x11-server
        apps/x11/server/main.c
        apps/x11/server/server_cli.c
        apps/x11/server/server_managed_client.c
        apps/x11/server/server_managed_ipc.c
        ${LIBRDP_X11_SERVER_PLATFORM_SOURCES}
    )
    librdp_configure_x11_server_target(librdp-x11-server)

    add_executable(librdp-x11-session-agent
        apps/x11/server/session_agent.c
        apps/x11/server/server_cli.c
        apps/x11/server/server_managed_ipc.c
        apps/x11/server/server_managed_process.c
        ${LIBRDP_X11_SERVER_PLATFORM_SOURCES}
    )
    librdp_configure_x11_server_target(librdp-x11-session-agent)

    add_executable(librdp-x11-session-broker
        apps/x11/server/session_broker.c
        apps/x11/server/server_managed_broker.c
        apps/x11/server/server_managed_config.c
        apps/x11/server/server_managed_ipc.c
        apps/x11/server/server_managed_policy.c
        apps/x11/server/server_managed_registry.c
    )
    librdp_configure_x11_managed_target(
        librdp-x11-session-broker)

    add_executable(librdp-x11-session-supervisor
        apps/x11/server/session_supervisor.c
        apps/x11/server/server_managed_auth.c
        apps/x11/server/server_managed_ipc.c
        apps/x11/server/server_managed_process.c
        apps/x11/server/server_managed_supervisor.c
    )
    librdp_configure_x11_managed_target(
        librdp-x11-session-supervisor)
    target_link_libraries(librdp-x11-session-supervisor PRIVATE
        PkgConfig::LIBRDP_X11_SERVER
    )
    librdp_apply_x11_managed_auth(
        librdp-x11-session-supervisor)

    install(TARGETS
        librdp-x11-server
        librdp-x11-session-agent
        librdp-x11-session-broker
        librdp-x11-session-supervisor
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    if(LIBRDP_BUILD_TESTS)
        find_program(LIBRDP_XVFB_EXECUTABLE NAMES Xvfb)

        add_executable(test_x11_managed
            tests/test_x11_managed.c
            apps/x11/server/server_managed_ipc.c
        )
        target_include_directories(test_x11_managed PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_x11_managed PRIVATE
            librdp
            OpenSSL::Crypto
        )
        librdp_apply_system_definitions(test_x11_managed)
        librdp_apply_warning_options(test_x11_managed)
        librdp_apply_sanitizer_compile_options(test_x11_managed)
        librdp_apply_sanitizer_link_options(test_x11_managed)
        add_test(NAME x11_managed COMMAND test_x11_managed)
        set_tests_properties(x11_managed PROPERTIES TIMEOUT 15)
        add_dependencies(librdp_tests test_x11_managed)

        add_executable(test_x11_managed_registry
            tests/test_x11_managed_registry.c
            apps/x11/server/server_managed_ipc.c
            apps/x11/server/server_managed_registry.c
        )
        target_include_directories(test_x11_managed_registry PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_x11_managed_registry PRIVATE
            librdp
            OpenSSL::Crypto
        )
        librdp_apply_system_definitions(test_x11_managed_registry)
        librdp_apply_warning_options(test_x11_managed_registry)
        librdp_apply_sanitizer_compile_options(test_x11_managed_registry)
        librdp_apply_sanitizer_link_options(test_x11_managed_registry)
        add_test(NAME x11_managed_registry
            COMMAND test_x11_managed_registry)
        set_tests_properties(x11_managed_registry PROPERTIES TIMEOUT 15)
        add_dependencies(librdp_tests test_x11_managed_registry)

        add_executable(test_x11_managed_policy
            tests/test_x11_managed_policy.c
            apps/x11/server/server_managed_ipc.c
            apps/x11/server/server_managed_policy.c
        )
        target_include_directories(test_x11_managed_policy PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_x11_managed_policy PRIVATE
            librdp
            OpenSSL::Crypto
        )
        librdp_apply_system_definitions(test_x11_managed_policy)
        librdp_apply_warning_options(test_x11_managed_policy)
        librdp_apply_sanitizer_compile_options(
            test_x11_managed_policy)
        librdp_apply_sanitizer_link_options(
            test_x11_managed_policy)
        add_test(NAME x11_managed_policy
            COMMAND test_x11_managed_policy)
        set_tests_properties(x11_managed_policy
            PROPERTIES TIMEOUT 15)
        add_dependencies(librdp_tests test_x11_managed_policy)

        add_executable(test_x11_managed_config
            tests/test_x11_managed_config.c
            apps/x11/server/server_managed_config.c
            apps/x11/server/server_managed_ipc.c
            apps/x11/server/server_managed_policy.c
        )
        target_include_directories(test_x11_managed_config PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_x11_managed_config PRIVATE
            librdp
            OpenSSL::Crypto
        )
        librdp_apply_system_definitions(test_x11_managed_config)
        librdp_apply_warning_options(test_x11_managed_config)
        librdp_apply_sanitizer_compile_options(
            test_x11_managed_config)
        librdp_apply_sanitizer_link_options(
            test_x11_managed_config)
        add_test(NAME x11_managed_config
            COMMAND test_x11_managed_config)
        set_tests_properties(x11_managed_config
            PROPERTIES TIMEOUT 15)
        add_dependencies(librdp_tests test_x11_managed_config)

        set(LIBRDP_X11_MANAGED_TEST_CONFIG_DIR
            ${CMAKE_CURRENT_BINARY_DIR}/x11-managed-config)
        file(MAKE_DIRECTORY
            ${LIBRDP_X11_MANAGED_TEST_CONFIG_DIR})
        file(COPY
            ${CMAKE_CURRENT_SOURCE_DIR}/packaging/librdp-x11-session-broker.conf.example
            DESTINATION ${LIBRDP_X11_MANAGED_TEST_CONFIG_DIR}
            FILE_PERMISSIONS OWNER_READ OWNER_WRITE
        )
        add_test(NAME x11_managed_config_cli
            COMMAND librdp-x11-session-broker
                --config
                ${LIBRDP_X11_MANAGED_TEST_CONFIG_DIR}/librdp-x11-session-broker.conf.example
                --check-config
        )
        set_tests_properties(x11_managed_config_cli
            PROPERTIES
                PASS_REGULAR_EXPRESSION "event=config.valid"
                TIMEOUT 15
        )

        add_executable(test_x11_managed_broker
            tests/test_x11_managed_broker.c
            apps/x11/server/server_managed_broker.c
            apps/x11/server/server_managed_ipc.c
            apps/x11/server/server_managed_policy.c
            apps/x11/server/server_managed_registry.c
        )
        librdp_configure_x11_managed_target(
            test_x11_managed_broker)
        target_compile_definitions(
            test_x11_managed_broker PRIVATE
            LIBRDP_TEST_MANAGED_BROKER_PATH=\"$<TARGET_FILE:test_x11_managed_broker>\"
        )
        add_test(NAME x11_managed_broker
            COMMAND test_x11_managed_broker)
        set_tests_properties(x11_managed_broker
            PROPERTIES TIMEOUT 30)
        add_dependencies(librdp_tests
            test_x11_managed_broker)

        add_executable(test_x11_managed_client
            tests/test_x11_managed_client.c
            apps/x11/server/server_cli.c
            apps/x11/server/server_managed_client.c
            apps/x11/server/server_managed_ipc.c
        )
        target_include_directories(
            test_x11_managed_client PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(
            test_x11_managed_client PRIVATE
            librdp
            OpenSSL::Crypto
            Threads::Threads
        )
        librdp_apply_system_definitions(
            test_x11_managed_client)
        librdp_apply_warning_options(
            test_x11_managed_client)
        librdp_apply_sanitizer_compile_options(
            test_x11_managed_client)
        librdp_apply_sanitizer_link_options(
            test_x11_managed_client)
        add_test(NAME x11_managed_client
            COMMAND test_x11_managed_client)
        set_tests_properties(x11_managed_client
            PROPERTIES TIMEOUT 15)
        add_dependencies(librdp_tests
            test_x11_managed_client)

        add_executable(test_x11_managed_auth
            tests/test_x11_managed_auth.c
            apps/x11/server/server_managed_auth.c
        )
        target_include_directories(test_x11_managed_auth PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_x11_managed_auth PRIVATE
            librdp
            OpenSSL::Crypto
        )
        librdp_apply_x11_managed_auth(test_x11_managed_auth)
        librdp_apply_system_definitions(test_x11_managed_auth)
        librdp_apply_warning_options(test_x11_managed_auth)
        librdp_apply_sanitizer_compile_options(test_x11_managed_auth)
        librdp_apply_sanitizer_link_options(test_x11_managed_auth)
        add_test(NAME x11_managed_auth COMMAND test_x11_managed_auth)
        set_tests_properties(x11_managed_auth PROPERTIES TIMEOUT 15)
        add_dependencies(librdp_tests test_x11_managed_auth)

        if(LIBRDP_XVFB_EXECUTABLE)
            add_executable(test_x11_managed_process
                tests/test_x11_managed_process.c
                apps/x11/server/server_managed_auth.c
                apps/x11/server/server_managed_process.c
            )
            target_include_directories(test_x11_managed_process PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/server
                ${CMAKE_CURRENT_SOURCE_DIR}/include
            )
            target_compile_definitions(test_x11_managed_process PRIVATE
                LIBRDP_TEST_MANAGED_PROCESS_PATH=\"$<TARGET_FILE:test_x11_managed_process>\"
                LIBRDP_TEST_XVFB_PATH="${LIBRDP_XVFB_EXECUTABLE}"
            )
            target_link_libraries(test_x11_managed_process PRIVATE
                librdp
                OpenSSL::Crypto
                PkgConfig::LIBRDP_X11_SERVER
            )
            librdp_apply_system_definitions(test_x11_managed_process)
            librdp_apply_warning_options(test_x11_managed_process)
            librdp_apply_sanitizer_compile_options(
                test_x11_managed_process)
            librdp_apply_sanitizer_link_options(
                test_x11_managed_process)
            add_test(NAME x11_managed_process
                COMMAND test_x11_managed_process)
            set_tests_properties(x11_managed_process
                PROPERTIES TIMEOUT 15)
            add_dependencies(librdp_tests test_x11_managed_process)

            add_executable(test_x11_managed_supervisor
                tests/test_x11_managed_supervisor.c
                apps/x11/server/server_managed_auth.c
                apps/x11/server/server_managed_ipc.c
                apps/x11/server/server_managed_process.c
                apps/x11/server/server_managed_supervisor.c
            )
            target_include_directories(test_x11_managed_supervisor PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/server
                ${CMAKE_CURRENT_SOURCE_DIR}/include
            )
            target_compile_definitions(
                test_x11_managed_supervisor PRIVATE
                LIBRDP_TEST_MANAGED_SUPERVISOR_PATH=\"$<TARGET_FILE:test_x11_managed_supervisor>\"
                LIBRDP_TEST_XVFB_PATH="${LIBRDP_XVFB_EXECUTABLE}"
            )
            target_link_libraries(test_x11_managed_supervisor PRIVATE
                librdp
                OpenSSL::Crypto
                PkgConfig::LIBRDP_X11_SERVER
            )
            librdp_apply_x11_managed_auth(
                test_x11_managed_supervisor)
            librdp_apply_system_definitions(
                test_x11_managed_supervisor)
            librdp_apply_warning_options(
                test_x11_managed_supervisor)
            librdp_apply_sanitizer_compile_options(
                test_x11_managed_supervisor)
            librdp_apply_sanitizer_link_options(
                test_x11_managed_supervisor)
            add_test(NAME x11_managed_supervisor
                COMMAND test_x11_managed_supervisor)
            set_tests_properties(x11_managed_supervisor
                PROPERTIES TIMEOUT 30)
            add_dependencies(librdp_tests
                test_x11_managed_supervisor)
        endif()

        if(LIBRDP_XVFB_EXECUTABLE)
            add_executable(test_x11_server
                tests/test_x11_server.c
                apps/x11/x11_keymap.c
                apps/x11/server/server_capture.c
                apps/x11/server/server_cli.c
                apps/x11/server/server_clipboard.c
                apps/x11/server/server_input.c
                apps/x11/server/server_permission.c
                apps/x11/server/server_pointer.c
                apps/common/server_fuse.c
                apps/x11/server/server_x11.c
            )
            target_include_directories(test_x11_server PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
                ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11
                ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/server
                ${CMAKE_CURRENT_SOURCE_DIR}/include
            )
            target_compile_definitions(test_x11_server PRIVATE
                LIBRDP_TEST_XVFB_PATH="${LIBRDP_XVFB_EXECUTABLE}"
                LIBRDP_SERVER_FUSE_TESTING=1
                LIBRDP_X11_SERVER_TESTING=1
            )
            target_link_libraries(test_x11_server PRIVATE
                librdp_app_common
                Iconv::Iconv
                PkgConfig::LIBRDP_X11_SERVER
            )
            if(LIBRDP_FUSE3_FOUND)
                target_compile_definitions(test_x11_server PRIVATE
                    LIBRDP_HAVE_FUSE3=1
                )
                target_link_libraries(test_x11_server PRIVATE
                    PkgConfig::LIBRDP_FUSE3
                )
            endif()
            if(LIBRDP_X11_SERVER_XSHM_FOUND)
                target_compile_definitions(test_x11_server PRIVATE
                    LIBRDP_HAVE_XSHM=1
                )
                target_link_libraries(test_x11_server PRIVATE
                    PkgConfig::LIBRDP_X11_SERVER_XEXT
                )
            endif()
            librdp_apply_system_definitions(test_x11_server)
            librdp_apply_warning_options(test_x11_server)
            librdp_apply_sanitizer_compile_options(test_x11_server)
            librdp_apply_sanitizer_link_options(test_x11_server)
            add_test(NAME x11_server COMMAND test_x11_server)
            set_tests_properties(x11_server PROPERTIES TIMEOUT 30)
            add_dependencies(librdp_tests test_x11_server)
        endif()
    endif()
endif()
