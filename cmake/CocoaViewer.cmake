# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_COCOA_VIEWER)
    if(NOT APPLE)
        message(FATAL_ERROR "LIBRDP_BUILD_COCOA_VIEWER=ON requires macOS")
    endif()
    enable_language(OBJC)
    find_library(LIBRDP_COCOA_FRAMEWORK Cocoa REQUIRED)
    add_executable(librdp-cocoa-viewer
        apps/cocoa/viewer/main.m
    )
    target_include_directories(librdp-cocoa-viewer PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(librdp-cocoa-viewer PRIVATE
        librdp
        ${LIBRDP_COCOA_FRAMEWORK}
    )
    librdp_apply_system_definitions(librdp-cocoa-viewer)
    librdp_apply_warning_options(librdp-cocoa-viewer)
    librdp_apply_sanitizer_compile_options(librdp-cocoa-viewer)
    librdp_apply_sanitizer_link_options(librdp-cocoa-viewer)
    install(TARGETS librdp-cocoa-viewer
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()
