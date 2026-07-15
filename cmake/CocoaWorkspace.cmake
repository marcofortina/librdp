# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_COCOA_WORKSPACE)
    if(NOT APPLE)
        message(FATAL_ERROR "LIBRDP_BUILD_COCOA_WORKSPACE=ON requires macOS")
    endif()
    enable_language(OBJC)
    find_library(LIBRDP_COCOA_FRAMEWORK Cocoa REQUIRED)
    add_executable(librdp-cocoa-workspace
        apps/cocoa/workspace/main.m
    )
    target_include_directories(librdp-cocoa-workspace PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(librdp-cocoa-workspace PRIVATE
        librdp
        ${LIBRDP_COCOA_FRAMEWORK}
    )
    librdp_apply_system_definitions(librdp-cocoa-workspace)
    librdp_apply_warning_options(librdp-cocoa-workspace)
    librdp_apply_sanitizer_compile_options(librdp-cocoa-workspace)
    librdp_apply_sanitizer_link_options(librdp-cocoa-workspace)
    install(TARGETS librdp-cocoa-workspace
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    if(LIBRDP_BUILD_TESTS)
        add_test(NAME cocoa_workspace_cli COMMAND librdp-cocoa-workspace --help)
        set_tests_properties(cocoa_workspace_cli PROPERTIES TIMEOUT 30)
    endif()
endif()
