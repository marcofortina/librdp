# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_ADMIN AND APPLE)
    enable_language(OBJC)
    find_library(LIBRDP_COCOA_FRAMEWORK Cocoa REQUIRED)
    add_executable(librdp-admin
        apps/cocoa/admin/main.m
    )
    target_include_directories(librdp-admin PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(librdp-admin PRIVATE
        librdp_app_common
        ${LIBRDP_COCOA_FRAMEWORK}
    )
    librdp_apply_system_definitions(librdp-admin)
    librdp_apply_warning_options(librdp-admin)
    librdp_apply_sanitizer_compile_options(librdp-admin)
    librdp_apply_sanitizer_link_options(librdp-admin)
    install(TARGETS librdp-admin
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    if(LIBRDP_BUILD_TESTS)
        add_test(NAME cocoa_admin_cli COMMAND librdp-admin --help)
        set_tests_properties(cocoa_admin_cli PROPERTIES TIMEOUT 30)
    endif()
endif()
