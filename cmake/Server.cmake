# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_TESTS OR LIBRDP_BUILD_SERVER)
    add_library(librdp_server_common STATIC
        apps/server/server_clipboard.c
        apps/server/server_clipboard_files.c
        apps/server/server_dirty.c
        apps/server/server_drive.c
        apps/server/server_host.c
        apps/server/server_host_loop.c
        apps/server/server_host_trace.c
        apps/server/server_options.c
        apps/server/server_platform.c
    )
    target_include_directories(librdp_server_common PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(librdp_server_common PUBLIC librdp)
    librdp_apply_system_definitions(librdp_server_common)
    librdp_apply_warning_options(librdp_server_common)
    librdp_apply_sanitizer_compile_options(librdp_server_common)
    librdp_apply_sanitizer_link_options(librdp_server_common)
endif()

if(LIBRDP_NATIVE_APP_BACKEND STREQUAL "cocoa" AND LIBRDP_BUILD_SERVER)
    enable_language(OBJC)
    find_library(LIBRDP_SERVER_COCOA_FRAMEWORK Cocoa REQUIRED)
    find_library(
        LIBRDP_SERVER_APPLICATIONSERVICES_FRAMEWORK
        ApplicationServices REQUIRED
    )
    find_library(LIBRDP_SERVER_CARBON_FRAMEWORK Carbon REQUIRED)
    find_library(LIBRDP_SERVER_COREGRAPHICS_FRAMEWORK CoreGraphics REQUIRED)
    find_library(LIBRDP_SERVER_COREMEDIA_FRAMEWORK CoreMedia REQUIRED)
    find_library(LIBRDP_SERVER_COREVIDEO_FRAMEWORK CoreVideo REQUIRED)
    find_library(
        LIBRDP_SERVER_SCREENCAPTUREKIT_FRAMEWORK
        ScreenCaptureKit REQUIRED
    )
endif()

if(LIBRDP_BUILD_TESTS AND LIBRDP_NATIVE_APP_BACKEND STREQUAL "cocoa")
    add_executable(test_cocoa_server_cli
        tests/test_cocoa_server_cli.c
        apps/server/cocoa_server_cli.c
    )
    target_include_directories(test_cocoa_server_cli PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(test_cocoa_server_cli PRIVATE
        librdp_server_common
    )
    librdp_apply_system_definitions(test_cocoa_server_cli)
    librdp_apply_warning_options(test_cocoa_server_cli)
    librdp_apply_sanitizer_compile_options(test_cocoa_server_cli)
    librdp_apply_sanitizer_link_options(test_cocoa_server_cli)
    add_test(NAME server_cli_parser COMMAND test_cocoa_server_cli)
    set_tests_properties(server_cli_parser PROPERTIES TIMEOUT 30)
endif()

if(LIBRDP_BUILD_SERVER AND LIBRDP_NATIVE_APP_BACKEND STREQUAL "cocoa")
    add_executable(librdp-server
        apps/server/cocoa_main.m
        apps/server/cocoa_capture.m
        apps/server/cocoa_clipboard.m
        apps/server/cocoa_input.m
        apps/server/cocoa_permission.m
        apps/server/cocoa_server.m
        apps/server/cocoa_server_cli.c
        apps/server/cocoa_server_runtime.m
        apps/server/server_fuse.c
    )
    librdp_set_application_backend(librdp-server cocoa)
    target_include_directories(librdp-server PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(librdp-server PRIVATE
        librdp_server_common
        ${LIBRDP_SERVER_APPLICATIONSERVICES_FRAMEWORK}
        ${LIBRDP_SERVER_COCOA_FRAMEWORK}
        ${LIBRDP_SERVER_CARBON_FRAMEWORK}
        ${LIBRDP_SERVER_COREGRAPHICS_FRAMEWORK}
        ${LIBRDP_SERVER_COREMEDIA_FRAMEWORK}
        ${LIBRDP_SERVER_COREVIDEO_FRAMEWORK}
        ${LIBRDP_SERVER_SCREENCAPTUREKIT_FRAMEWORK}
        Threads::Threads
    )
    if(LIBRDP_FUSE3_FOUND)
        target_compile_definitions(librdp-server PRIVATE
            LIBRDP_HAVE_FUSE3=1
        )
        target_link_libraries(librdp-server PRIVATE
            PkgConfig::LIBRDP_FUSE3
        )
    endif()
    target_compile_options(librdp-server PRIVATE
        $<$<COMPILE_LANGUAGE:OBJC>:-fblocks>
        $<$<COMPILE_LANGUAGE:OBJC>:-mmacosx-version-min=12.3>
    )
    target_link_options(librdp-server PRIVATE
        -mmacosx-version-min=12.3
    )
    librdp_apply_system_definitions(librdp-server)
    librdp_apply_warning_options(librdp-server)
    librdp_apply_sanitizer_compile_options(librdp-server)
    librdp_apply_sanitizer_link_options(librdp-server)
    install(TARGETS librdp-server
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    if(LIBRDP_BUILD_TESTS)
        add_executable(test_cocoa_server_input
            tests/test_cocoa_server_input.m
            apps/server/cocoa_input.m
            apps/server/cocoa_permission.m
        )
        target_compile_definitions(test_cocoa_server_input PRIVATE
            LIBRDP_COCOA_SERVER_TESTING=1
        )
        target_include_directories(test_cocoa_server_input PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_cocoa_server_input PRIVATE
            librdp_server_common
            ${LIBRDP_SERVER_APPLICATIONSERVICES_FRAMEWORK}
            ${LIBRDP_SERVER_COCOA_FRAMEWORK}
            ${LIBRDP_SERVER_CARBON_FRAMEWORK}
            ${LIBRDP_SERVER_COREGRAPHICS_FRAMEWORK}
            ${LIBRDP_SERVER_SCREENCAPTUREKIT_FRAMEWORK}
        )
        target_compile_options(test_cocoa_server_input PRIVATE
            $<$<COMPILE_LANGUAGE:OBJC>:-fblocks>
            $<$<COMPILE_LANGUAGE:OBJC>:-mmacosx-version-min=12.3>
        )
        target_link_options(test_cocoa_server_input PRIVATE
            -mmacosx-version-min=12.3
        )
        librdp_apply_system_definitions(test_cocoa_server_input)
        librdp_apply_warning_options(test_cocoa_server_input)
        librdp_apply_sanitizer_compile_options(test_cocoa_server_input)
        librdp_apply_sanitizer_link_options(test_cocoa_server_input)
        add_test(NAME cocoa_server_input
            COMMAND test_cocoa_server_input)
        set_tests_properties(cocoa_server_input PROPERTIES TIMEOUT 30)

        add_executable(test_cocoa_server_capture
            tests/test_cocoa_server_capture.m
            apps/server/cocoa_capture.m
        )
        target_compile_definitions(test_cocoa_server_capture PRIVATE
            LIBRDP_COCOA_SERVER_TESTING=1
        )
        target_include_directories(test_cocoa_server_capture PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_cocoa_server_capture PRIVATE
            librdp_server_common
            ${LIBRDP_SERVER_COCOA_FRAMEWORK}
            ${LIBRDP_SERVER_COREGRAPHICS_FRAMEWORK}
            ${LIBRDP_SERVER_COREMEDIA_FRAMEWORK}
            ${LIBRDP_SERVER_COREVIDEO_FRAMEWORK}
            ${LIBRDP_SERVER_SCREENCAPTUREKIT_FRAMEWORK}
            Threads::Threads
        )
        target_compile_options(test_cocoa_server_capture PRIVATE
            $<$<COMPILE_LANGUAGE:OBJC>:-fblocks>
            $<$<COMPILE_LANGUAGE:OBJC>:-mmacosx-version-min=12.3>
        )
        target_link_options(test_cocoa_server_capture PRIVATE
            -mmacosx-version-min=12.3
        )
        librdp_apply_system_definitions(test_cocoa_server_capture)
        librdp_apply_warning_options(test_cocoa_server_capture)
        librdp_apply_sanitizer_compile_options(
            test_cocoa_server_capture)
        librdp_apply_sanitizer_link_options(
            test_cocoa_server_capture)
        add_test(NAME cocoa_server_capture
            COMMAND test_cocoa_server_capture)
        set_tests_properties(cocoa_server_capture
            PROPERTIES TIMEOUT 30)

        add_executable(test_cocoa_server_permission
            tests/test_cocoa_server_permission.m
            apps/server/cocoa_permission.m
        )
        target_compile_definitions(test_cocoa_server_permission PRIVATE
            LIBRDP_COCOA_SERVER_TESTING=1
        )
        target_include_directories(test_cocoa_server_permission PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_cocoa_server_permission PRIVATE
            librdp_server_common
            ${LIBRDP_SERVER_APPLICATIONSERVICES_FRAMEWORK}
            ${LIBRDP_SERVER_COCOA_FRAMEWORK}
            ${LIBRDP_SERVER_COREGRAPHICS_FRAMEWORK}
        )
        target_compile_options(test_cocoa_server_permission PRIVATE
            $<$<COMPILE_LANGUAGE:OBJC>:-fblocks>
            $<$<COMPILE_LANGUAGE:OBJC>:-mmacosx-version-min=12.3>
        )
        target_link_options(test_cocoa_server_permission PRIVATE
            -mmacosx-version-min=12.3
        )
        librdp_apply_system_definitions(test_cocoa_server_permission)
        librdp_apply_warning_options(test_cocoa_server_permission)
        librdp_apply_sanitizer_compile_options(
            test_cocoa_server_permission)
        librdp_apply_sanitizer_link_options(
            test_cocoa_server_permission)
        add_test(NAME cocoa_server_permission
            COMMAND test_cocoa_server_permission)
        set_tests_properties(cocoa_server_permission
            PROPERTIES TIMEOUT 30)

        add_executable(test_cocoa_server_clipboard
            tests/test_cocoa_server_clipboard.m
            apps/server/cocoa_clipboard.m
        )
        target_compile_definitions(test_cocoa_server_clipboard PRIVATE
            LIBRDP_COCOA_SERVER_TESTING=1
        )
        target_include_directories(test_cocoa_server_clipboard PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_cocoa_server_clipboard PRIVATE
            librdp_server_common
            ${LIBRDP_SERVER_COCOA_FRAMEWORK}
            Threads::Threads
        )
        target_compile_options(test_cocoa_server_clipboard PRIVATE
            $<$<COMPILE_LANGUAGE:OBJC>:-fblocks>
            $<$<COMPILE_LANGUAGE:OBJC>:-mmacosx-version-min=12.3>
        )
        target_link_options(test_cocoa_server_clipboard PRIVATE
            -mmacosx-version-min=12.3
        )
        librdp_apply_system_definitions(test_cocoa_server_clipboard)
        librdp_apply_warning_options(test_cocoa_server_clipboard)
        librdp_apply_sanitizer_compile_options(test_cocoa_server_clipboard)
        librdp_apply_sanitizer_link_options(test_cocoa_server_clipboard)
        add_test(NAME cocoa_server_clipboard
            COMMAND test_cocoa_server_clipboard)
        set_tests_properties(cocoa_server_clipboard
            PROPERTIES TIMEOUT 30)

        add_test(NAME server_cli COMMAND librdp-server --help)
        set_tests_properties(server_cli PROPERTIES TIMEOUT 30)
    endif()
endif()

if(LIBRDP_BUILD_SERVER AND LIBRDP_NATIVE_APP_BACKEND STREQUAL "x11")
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

    set(LIBRDP_X11_SESSION_LIBEXEC_DIR
        "${CMAKE_INSTALL_FULL_LIBEXECDIR}/librdp")

    function(librdp_apply_x11_managed_paths target)
        target_compile_definitions(${target} PRIVATE
            LIBRDP_X11_SESSION_SUPERVISOR_PATH="${LIBRDP_X11_SESSION_LIBEXEC_DIR}/librdp-session-supervisor"
            LIBRDP_X11_SESSION_AGENT_PATH="${LIBRDP_X11_SESSION_LIBEXEC_DIR}/librdp-session-agent"
        )
    endfunction()

    set(LIBRDP_X11_SERVER_PLATFORM_SOURCES
        apps/common/x11_keymap.c
        apps/server/x11_capture.c
        apps/server/x11_clipboard.c
        apps/server/x11_input.c
        apps/server/x11_permission.c
        apps/server/x11_pointer.c
        apps/server/server_fuse.c
        apps/server/x11_runtime.c
        apps/server/x11_server.c
    )

    function(librdp_configure_x11_server_target target)
        target_include_directories(${target} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(${target} PRIVATE
            librdp_server_common
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
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(${target} PRIVATE
            librdp
            OpenSSL::Crypto
            Threads::Threads
        )
        librdp_apply_x11_managed_paths(${target})
        librdp_apply_system_definitions(${target})
        librdp_apply_warning_options(${target})
        librdp_apply_sanitizer_compile_options(${target})
        librdp_apply_sanitizer_link_options(${target})
    endfunction()

    add_executable(librdp-server
        apps/server/x11_main.c
        apps/server/x11_cli.c
        apps/server/x11_managed_client.c
        apps/server/x11_managed_ipc.c
        ${LIBRDP_X11_SERVER_PLATFORM_SOURCES}
    )
    librdp_set_application_backend(librdp-server x11)
    librdp_configure_x11_server_target(librdp-server)

    add_executable(librdp-session-agent
        apps/server/x11_session_agent.c
        apps/server/x11_cli.c
        apps/server/x11_managed_ipc.c
        apps/server/x11_managed_process.c
        ${LIBRDP_X11_SERVER_PLATFORM_SOURCES}
    )
    librdp_configure_x11_server_target(librdp-session-agent)

    add_executable(librdp-session-broker
        apps/server/x11_session_broker.c
        apps/server/x11_managed_broker.c
        apps/server/x11_managed_config.c
        apps/server/x11_managed_ipc.c
        apps/server/x11_managed_policy.c
        apps/server/x11_managed_registry.c
    )
    librdp_configure_x11_managed_target(
        librdp-session-broker)

    add_executable(librdp-session-supervisor
        apps/server/x11_session_supervisor.c
        apps/server/x11_managed_auth.c
        apps/server/x11_managed_ipc.c
        apps/server/x11_managed_process.c
        apps/server/x11_managed_supervisor.c
    )
    librdp_configure_x11_managed_target(
        librdp-session-supervisor)
    target_link_libraries(librdp-session-supervisor PRIVATE
        PkgConfig::LIBRDP_X11_SERVER
    )
    librdp_apply_x11_managed_auth(
        librdp-session-supervisor)

    install(TARGETS librdp-server
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    install(TARGETS librdp-session-broker
        RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
    )
    install(TARGETS
        librdp-session-agent
        librdp-session-supervisor
        RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/librdp
    )
    if(LIBRDP_BUILD_TESTS)
        find_program(LIBRDP_XVFB_EXECUTABLE NAMES Xvfb)
        add_test(NAME server_cli COMMAND librdp-server --help)
        set_tests_properties(server_cli PROPERTIES TIMEOUT 30)

        add_executable(test_x11_managed
            tests/test_x11_managed.c
            apps/server/x11_managed_ipc.c
        )
        target_include_directories(test_x11_managed PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
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
            apps/server/x11_managed_ipc.c
            apps/server/x11_managed_registry.c
        )
        target_include_directories(test_x11_managed_registry PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
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
            apps/server/x11_managed_ipc.c
            apps/server/x11_managed_policy.c
        )
        target_include_directories(test_x11_managed_policy PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_x11_managed_policy PRIVATE
            librdp
            OpenSSL::Crypto
        )
        librdp_apply_x11_managed_paths(test_x11_managed_policy)
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
            apps/server/x11_managed_config.c
            apps/server/x11_managed_ipc.c
            apps/server/x11_managed_policy.c
        )
        target_include_directories(test_x11_managed_config PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_x11_managed_config PRIVATE
            librdp
            OpenSSL::Crypto
        )
        librdp_apply_x11_managed_paths(test_x11_managed_config)
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
            ${CMAKE_CURRENT_BINARY_DIR}/librdp-session-broker.conf.example
            DESTINATION ${LIBRDP_X11_MANAGED_TEST_CONFIG_DIR}
            FILE_PERMISSIONS OWNER_READ OWNER_WRITE
        )
        add_test(NAME x11_managed_config_cli
            COMMAND librdp-session-broker
                --config
                ${LIBRDP_X11_MANAGED_TEST_CONFIG_DIR}/librdp-session-broker.conf.example
                --check-config
        )
        set_tests_properties(x11_managed_config_cli
            PROPERTIES
                PASS_REGULAR_EXPRESSION "event=config.valid"
                TIMEOUT 15
        )

        add_executable(test_x11_managed_broker
            tests/test_x11_managed_broker.c
            apps/server/x11_managed_broker.c
            apps/server/x11_managed_ipc.c
            apps/server/x11_managed_policy.c
            apps/server/x11_managed_registry.c
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
            apps/server/x11_cli.c
            apps/server/x11_managed_client.c
            apps/server/x11_managed_ipc.c
        )
        target_include_directories(
            test_x11_managed_client PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(
            test_x11_managed_client PRIVATE
            librdp_server_common
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
            apps/server/x11_managed_auth.c
        )
        target_include_directories(test_x11_managed_auth PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
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
                apps/server/x11_managed_auth.c
                apps/server/x11_managed_process.c
            )
            target_include_directories(test_x11_managed_process PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
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
                apps/server/x11_managed_auth.c
                apps/server/x11_managed_ipc.c
                apps/server/x11_managed_process.c
                apps/server/x11_managed_supervisor.c
            )
            target_include_directories(test_x11_managed_supervisor PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
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
            librdp_apply_x11_managed_paths(
                test_x11_managed_supervisor)
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
                apps/common/x11_keymap.c
                apps/server/x11_capture.c
                apps/server/x11_cli.c
                apps/server/x11_clipboard.c
                apps/server/x11_input.c
                apps/server/x11_permission.c
                apps/server/x11_pointer.c
                apps/server/server_fuse.c
                apps/server/x11_server.c
            )
            target_include_directories(test_x11_server PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
                ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
                ${CMAKE_CURRENT_SOURCE_DIR}/include
            )
            target_compile_definitions(test_x11_server PRIVATE
                LIBRDP_TEST_XVFB_PATH="${LIBRDP_XVFB_EXECUTABLE}"
                LIBRDP_SERVER_FUSE_TESTING=1
                LIBRDP_X11_SERVER_TESTING=1
            )
            target_link_libraries(test_x11_server PRIVATE
                librdp_server_common
                Iconv::Iconv
                OpenSSL::Crypto
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

            if(LIBRDP_FUSE3_FOUND)
                find_program(LIBRDP_OPENSSL_EXECUTABLE NAMES openssl)
                add_executable(test_x11_server_interop
                    tests/test_x11_server_interop.c
                )
                target_compile_definitions(
                    test_x11_server_interop PRIVATE
                    LIBRDP_TEST_XVFB_PATH="${LIBRDP_XVFB_EXECUTABLE}"
                    LIBRDP_TEST_X11_SERVER_PATH="$<TARGET_FILE:librdp-server>"
                )
                if(LIBRDP_OPENSSL_EXECUTABLE)
                    target_compile_definitions(
                        test_x11_server_interop PRIVATE
                        LIBRDP_TEST_OPENSSL_PATH="${LIBRDP_OPENSSL_EXECUTABLE}"
                    )
                else()
                    target_compile_definitions(
                        test_x11_server_interop PRIVATE
                        LIBRDP_TEST_OPENSSL_PATH="openssl"
                    )
                endif()
                target_link_libraries(test_x11_server_interop PRIVATE
                    PkgConfig::LIBRDP_X11_SERVER
                )
                librdp_apply_system_definitions(
                    test_x11_server_interop)
                librdp_apply_warning_options(
                    test_x11_server_interop)
                librdp_apply_sanitizer_compile_options(
                    test_x11_server_interop)
                librdp_apply_sanitizer_link_options(
                    test_x11_server_interop)
                add_test(NAME x11_server_external_interop
                    COMMAND test_x11_server_interop standard)
                add_test(NAME x11_server_external_interop_writable
                    COMMAND test_x11_server_interop standard-writable)
                set(LIBRDP_X11_SERVER_INTEROP_TESTS
                    x11_server_external_interop
                    x11_server_external_interop_writable
                )
                if(LIBRDP_OPENSSL_EXECUTABLE)
                    add_test(NAME x11_server_external_interop_tls
                        COMMAND test_x11_server_interop tls)
                    add_test(NAME x11_server_external_interop_nla
                        COMMAND test_x11_server_interop nla)
                    list(APPEND LIBRDP_X11_SERVER_INTEROP_TESTS
                        x11_server_external_interop_tls
                        x11_server_external_interop_nla
                    )
                endif()
                set_tests_properties(
                    ${LIBRDP_X11_SERVER_INTEROP_TESTS}
                    PROPERTIES
                    SKIP_RETURN_CODE 77
                    TIMEOUT 45
                )
                add_dependencies(librdp_tests
                    test_x11_server_interop)
            endif()
        endif()
    endif()
endif()
