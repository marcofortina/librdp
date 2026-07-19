# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_TESTS OR LIBRDP_BUILD_WORKSPACE)
    add_library(librdp_workspace_common STATIC
        apps/workspace/workspace_app.c
        apps/workspace/workspace_options.c
    )
    target_include_directories(librdp_workspace_common PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/workspace
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(librdp_workspace_common PUBLIC librdp)
    librdp_apply_system_definitions(librdp_workspace_common)
    librdp_apply_warning_options(librdp_workspace_common)
    librdp_apply_sanitizer_compile_options(librdp_workspace_common)
    librdp_apply_sanitizer_link_options(librdp_workspace_common)
endif()

if(LIBRDP_BUILD_WORKSPACE AND LIBRDP_NATIVE_APP_BACKEND STREQUAL "x11")
    find_package(X11 REQUIRED)
    add_executable(librdp-workspace
        apps/workspace/x11_main.c
    )
    librdp_set_application_backend(librdp-workspace x11)
    target_include_directories(librdp-workspace PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/workspace
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${X11_INCLUDE_DIR}
    )
    target_link_libraries(librdp-workspace PRIVATE
        librdp_workspace_common
        ${X11_LIBRARIES}
    )
    librdp_apply_system_definitions(librdp-workspace)
    get_target_property(LIBRDP_X11_WORKSPACE_INCLUDES librdp-workspace INCLUDE_DIRECTORIES)
    foreach(LIBRDP_X11_WORKSPACE_INCLUDE IN LISTS LIBRDP_X11_WORKSPACE_INCLUDES)
        if(NOT IS_ABSOLUTE "${LIBRDP_X11_WORKSPACE_INCLUDE}")
            continue()
        endif()
        file(REAL_PATH "${LIBRDP_X11_WORKSPACE_INCLUDE}" LIBRDP_X11_WORKSPACE_INCLUDE_REAL)
        file(REAL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src" LIBRDP_SOURCE_PRIVATE_INCLUDE_REAL)
        string(FIND "${LIBRDP_X11_WORKSPACE_INCLUDE_REAL}/"
            "${LIBRDP_SOURCE_PRIVATE_INCLUDE_REAL}/" LIBRDP_X11_WORKSPACE_PRIVATE_INCLUDE_INDEX)
        if(LIBRDP_X11_WORKSPACE_PRIVATE_INCLUDE_INDEX EQUAL 0)
            message(FATAL_ERROR "librdp-workspace must not include private src headers")
        endif()
    endforeach()
    librdp_apply_warning_options(librdp-workspace)
    librdp_apply_sanitizer_compile_options(librdp-workspace)
    librdp_apply_sanitizer_link_options(librdp-workspace)
    install(TARGETS librdp-workspace
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    if(LIBRDP_BUILD_TESTS)
        add_test(NAME workspace_cli COMMAND librdp-workspace --help)
        set_tests_properties(workspace_cli PROPERTIES TIMEOUT 10)
    endif()
endif()

if(LIBRDP_BUILD_WORKSPACE AND LIBRDP_NATIVE_APP_BACKEND STREQUAL "cocoa")
    enable_language(OBJC)
    find_library(LIBRDP_WORKSPACE_COCOA_FRAMEWORK Cocoa REQUIRED)
    add_executable(librdp-workspace
        apps/workspace/cocoa_main.m
    )
    librdp_set_application_backend(librdp-workspace cocoa)
    target_include_directories(librdp-workspace PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/workspace
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(librdp-workspace PRIVATE
        librdp_workspace_common
        ${LIBRDP_WORKSPACE_COCOA_FRAMEWORK}
    )
    librdp_apply_system_definitions(librdp-workspace)
    librdp_apply_warning_options(librdp-workspace)
    librdp_apply_sanitizer_compile_options(librdp-workspace)
    librdp_apply_sanitizer_link_options(librdp-workspace)
    install(TARGETS librdp-workspace
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    if(LIBRDP_BUILD_TESTS)
        add_test(NAME workspace_cli COMMAND librdp-workspace --help)
        set_tests_properties(workspace_cli PROPERTIES TIMEOUT 30)
    endif()
endif()
