# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_WORKSPACE AND APPLE)
    enable_language(OBJC)
    find_library(LIBRDP_COCOA_FRAMEWORK Cocoa REQUIRED)
    add_executable(librdp-workspace
        apps/workspace/cocoa_main.m
    )
    target_include_directories(librdp-workspace PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/workspace
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(librdp-workspace PRIVATE
        librdp_app_common
        ${LIBRDP_COCOA_FRAMEWORK}
    )
    librdp_apply_system_definitions(librdp-workspace)
    librdp_apply_warning_options(librdp-workspace)
    librdp_apply_sanitizer_compile_options(librdp-workspace)
    librdp_apply_sanitizer_link_options(librdp-workspace)
    install(TARGETS librdp-workspace
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    if(LIBRDP_BUILD_TESTS)
        add_test(NAME cocoa_workspace_cli COMMAND librdp-workspace --help)
        set_tests_properties(cocoa_workspace_cli PROPERTIES TIMEOUT 30)
    endif()
endif()
