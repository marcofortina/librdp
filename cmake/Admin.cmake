# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_TESTS OR LIBRDP_BUILD_ADMIN)
    add_library(librdp_admin_common STATIC
        apps/admin/admin_app.c
        apps/admin/admin_options.c
    )
    target_include_directories(librdp_admin_common PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/admin
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(librdp_admin_common PUBLIC librdp)
    librdp_apply_system_definitions(librdp_admin_common)
    librdp_apply_warning_options(librdp_admin_common)
    librdp_apply_sanitizer_compile_options(librdp_admin_common)
    librdp_apply_sanitizer_link_options(librdp_admin_common)
endif()

if(LIBRDP_BUILD_ADMIN AND LIBRDP_NATIVE_APP_BACKEND STREQUAL "x11")
    find_package(X11 REQUIRED)
    add_executable(librdp-admin
        apps/admin/x11_main.c
    )
    librdp_set_application_backend(librdp-admin x11)
    target_include_directories(librdp-admin PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/admin
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${X11_INCLUDE_DIR}
    )
    target_link_libraries(librdp-admin PRIVATE
        librdp_admin_common
        ${X11_LIBRARIES}
    )
    librdp_apply_system_definitions(librdp-admin)
    get_target_property(LIBRDP_X11_ADMIN_INCLUDES librdp-admin INCLUDE_DIRECTORIES)
    foreach(LIBRDP_X11_ADMIN_INCLUDE IN LISTS LIBRDP_X11_ADMIN_INCLUDES)
        if(NOT IS_ABSOLUTE "${LIBRDP_X11_ADMIN_INCLUDE}")
            continue()
        endif()
        file(REAL_PATH "${LIBRDP_X11_ADMIN_INCLUDE}" LIBRDP_X11_ADMIN_INCLUDE_REAL)
        file(REAL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src" LIBRDP_SOURCE_PRIVATE_INCLUDE_REAL)
        string(FIND "${LIBRDP_X11_ADMIN_INCLUDE_REAL}/"
            "${LIBRDP_SOURCE_PRIVATE_INCLUDE_REAL}/" LIBRDP_X11_ADMIN_PRIVATE_INCLUDE_INDEX)
        if(LIBRDP_X11_ADMIN_PRIVATE_INCLUDE_INDEX EQUAL 0)
            message(FATAL_ERROR "librdp-admin must not include private src headers")
        endif()
    endforeach()
    librdp_apply_warning_options(librdp-admin)
    librdp_apply_sanitizer_compile_options(librdp-admin)
    librdp_apply_sanitizer_link_options(librdp-admin)
    install(TARGETS librdp-admin
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    if(LIBRDP_BUILD_TESTS)
        add_test(NAME admin_cli COMMAND librdp-admin --help)
        set_tests_properties(admin_cli PROPERTIES TIMEOUT 10)
    endif()
endif()

if(LIBRDP_BUILD_ADMIN AND LIBRDP_NATIVE_APP_BACKEND STREQUAL "cocoa")
    enable_language(OBJC)
    find_library(LIBRDP_ADMIN_COCOA_FRAMEWORK Cocoa REQUIRED)
    add_executable(librdp-admin
        apps/admin/cocoa_main.m
    )
    librdp_set_application_backend(librdp-admin cocoa)
    target_include_directories(librdp-admin PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/admin
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(librdp-admin PRIVATE
        librdp_admin_common
        ${LIBRDP_ADMIN_COCOA_FRAMEWORK}
    )
    librdp_apply_system_definitions(librdp-admin)
    librdp_apply_warning_options(librdp-admin)
    librdp_apply_sanitizer_compile_options(librdp-admin)
    librdp_apply_sanitizer_link_options(librdp-admin)
    install(TARGETS librdp-admin
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    if(LIBRDP_BUILD_TESTS)
        add_test(NAME admin_cli COMMAND librdp-admin --help)
        set_tests_properties(admin_cli PROPERTIES TIMEOUT 30)
    endif()
endif()
