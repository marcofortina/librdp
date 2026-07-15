# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_COCOA_ADMIN)
    if(NOT APPLE)
        message(FATAL_ERROR "LIBRDP_BUILD_COCOA_ADMIN=ON requires macOS")
    endif()
    enable_language(OBJC)
    find_library(LIBRDP_COCOA_FRAMEWORK Cocoa REQUIRED)
    add_executable(librdp-cocoa-admin
        apps/cocoa/admin/main.m
    )
    target_include_directories(librdp-cocoa-admin PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(librdp-cocoa-admin PRIVATE
        librdp
        ${LIBRDP_COCOA_FRAMEWORK}
    )
    librdp_apply_system_definitions(librdp-cocoa-admin)
    librdp_apply_warning_options(librdp-cocoa-admin)
    librdp_apply_sanitizer_compile_options(librdp-cocoa-admin)
    librdp_apply_sanitizer_link_options(librdp-cocoa-admin)
    install(TARGETS librdp-cocoa-admin
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    if(LIBRDP_BUILD_TESTS)
        add_test(NAME cocoa_admin_cli COMMAND librdp-cocoa-admin --help)
        set_tests_properties(cocoa_admin_cli PROPERTIES TIMEOUT 30)
    endif()
endif()
