# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_TESTS)
    add_executable(test_cocoa_server_cli
        tests/test_cocoa_server_cli.c
        apps/cocoa/server/cocoa_server_cli.c
    )
    target_include_directories(test_cocoa_server_cli PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/cocoa/server
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(test_cocoa_server_cli PRIVATE
        librdp_app_common
    )
    librdp_apply_system_definitions(test_cocoa_server_cli)
    librdp_apply_warning_options(test_cocoa_server_cli)
    librdp_apply_sanitizer_compile_options(test_cocoa_server_cli)
    librdp_apply_sanitizer_link_options(test_cocoa_server_cli)
    add_test(NAME cocoa_server_cli COMMAND test_cocoa_server_cli)
    set_tests_properties(cocoa_server_cli PROPERTIES TIMEOUT 30)
    add_dependencies(librdp_tests test_cocoa_server_cli)
endif()

if(LIBRDP_BUILD_SERVER AND APPLE)
    enable_language(OBJC)
    find_library(LIBRDP_COCOA_SERVER_COCOA_FRAMEWORK Cocoa REQUIRED)
    find_library(
        LIBRDP_COCOA_SERVER_APPLICATIONSERVICES_FRAMEWORK
        ApplicationServices REQUIRED
    )
    find_library(LIBRDP_COCOA_SERVER_CARBON_FRAMEWORK Carbon REQUIRED)
    find_library(LIBRDP_COCOA_SERVER_COREGRAPHICS_FRAMEWORK CoreGraphics REQUIRED)
    find_library(LIBRDP_COCOA_SERVER_COREMEDIA_FRAMEWORK CoreMedia REQUIRED)
    find_library(LIBRDP_COCOA_SERVER_COREVIDEO_FRAMEWORK CoreVideo REQUIRED)
    find_library(LIBRDP_COCOA_SERVER_SCREENCAPTUREKIT_FRAMEWORK ScreenCaptureKit REQUIRED)
    add_executable(librdp-server
        apps/cocoa/server/main.m
        apps/cocoa/server/cocoa_capture.m
        apps/cocoa/server/cocoa_clipboard.m
        apps/cocoa/server/cocoa_input.m
        apps/cocoa/server/cocoa_permission.m
        apps/cocoa/server/cocoa_server.m
        apps/cocoa/server/cocoa_server_cli.c
        apps/cocoa/server/cocoa_server_runtime.m
        apps/common/server_fuse.c
    )
    target_include_directories(librdp-server PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/cocoa/server
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(librdp-server PRIVATE
        librdp_app_common
        ${LIBRDP_COCOA_SERVER_APPLICATIONSERVICES_FRAMEWORK}
        ${LIBRDP_COCOA_SERVER_COCOA_FRAMEWORK}
        ${LIBRDP_COCOA_SERVER_CARBON_FRAMEWORK}
        ${LIBRDP_COCOA_SERVER_COREGRAPHICS_FRAMEWORK}
        ${LIBRDP_COCOA_SERVER_COREMEDIA_FRAMEWORK}
        ${LIBRDP_COCOA_SERVER_COREVIDEO_FRAMEWORK}
        ${LIBRDP_COCOA_SERVER_SCREENCAPTUREKIT_FRAMEWORK}
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
            apps/cocoa/server/cocoa_input.m
            apps/cocoa/server/cocoa_permission.m
        )
        target_compile_definitions(test_cocoa_server_input PRIVATE
            LIBRDP_COCOA_SERVER_TESTING=1
        )
        target_include_directories(test_cocoa_server_input PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/cocoa/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_cocoa_server_input PRIVATE
            librdp_app_common
            ${LIBRDP_COCOA_SERVER_APPLICATIONSERVICES_FRAMEWORK}
            ${LIBRDP_COCOA_SERVER_COCOA_FRAMEWORK}
            ${LIBRDP_COCOA_SERVER_CARBON_FRAMEWORK}
            ${LIBRDP_COCOA_SERVER_COREGRAPHICS_FRAMEWORK}
            ${LIBRDP_COCOA_SERVER_SCREENCAPTUREKIT_FRAMEWORK}
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
        add_dependencies(librdp_tests test_cocoa_server_input)
        add_executable(test_cocoa_server_capture
            tests/test_cocoa_server_capture.m
            apps/cocoa/server/cocoa_capture.m
        )
        target_compile_definitions(test_cocoa_server_capture PRIVATE
            LIBRDP_COCOA_SERVER_TESTING=1
        )
        target_include_directories(test_cocoa_server_capture PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/cocoa/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_cocoa_server_capture PRIVATE
            librdp_app_common
            ${LIBRDP_COCOA_SERVER_COCOA_FRAMEWORK}
            ${LIBRDP_COCOA_SERVER_COREGRAPHICS_FRAMEWORK}
            ${LIBRDP_COCOA_SERVER_COREMEDIA_FRAMEWORK}
            ${LIBRDP_COCOA_SERVER_COREVIDEO_FRAMEWORK}
            ${LIBRDP_COCOA_SERVER_SCREENCAPTUREKIT_FRAMEWORK}
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
        add_dependencies(librdp_tests
            test_cocoa_server_capture)
        add_executable(test_cocoa_server_permission
            tests/test_cocoa_server_permission.m
            apps/cocoa/server/cocoa_permission.m
        )
        target_compile_definitions(test_cocoa_server_permission PRIVATE
            LIBRDP_COCOA_SERVER_TESTING=1
        )
        target_include_directories(test_cocoa_server_permission PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/cocoa/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_cocoa_server_permission PRIVATE
            librdp_app_common
            ${LIBRDP_COCOA_SERVER_APPLICATIONSERVICES_FRAMEWORK}
            ${LIBRDP_COCOA_SERVER_COCOA_FRAMEWORK}
            ${LIBRDP_COCOA_SERVER_COREGRAPHICS_FRAMEWORK}
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
        add_dependencies(librdp_tests
            test_cocoa_server_permission)
        add_executable(test_cocoa_server_clipboard
            tests/test_cocoa_server_clipboard.m
            apps/cocoa/server/cocoa_clipboard.m
        )
        target_compile_definitions(test_cocoa_server_clipboard PRIVATE
            LIBRDP_COCOA_SERVER_TESTING=1
        )
        target_include_directories(test_cocoa_server_clipboard PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/cocoa/server
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_cocoa_server_clipboard PRIVATE
            librdp_app_common
            ${LIBRDP_COCOA_SERVER_COCOA_FRAMEWORK}
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
        add_dependencies(librdp_tests
            test_cocoa_server_clipboard)
        add_test(NAME cocoa_server_help
            COMMAND librdp-server --help)
        set_tests_properties(cocoa_server_help PROPERTIES TIMEOUT 30)
    endif()
endif()
