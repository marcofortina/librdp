# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_MACOS_VIEWER)
    if(NOT APPLE)
        message(FATAL_ERROR "LIBRDP_BUILD_MACOS_VIEWER=ON requires macOS")
    endif()
    enable_language(OBJC)
    find_library(LIBRDP_COCOA_FRAMEWORK Cocoa REQUIRED)
    add_executable(librdp-macos-viewer
        apps/macos-viewer/main.m
    )
    target_include_directories(librdp-macos-viewer PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(librdp-macos-viewer PRIVATE
        librdp
        ${LIBRDP_COCOA_FRAMEWORK}
    )
    librdp_apply_system_definitions(librdp-macos-viewer)
    librdp_apply_warning_options(librdp-macos-viewer)
    librdp_apply_sanitizer_compile_options(librdp-macos-viewer)
    librdp_apply_sanitizer_link_options(librdp-macos-viewer)
    install(TARGETS librdp-macos-viewer
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()
