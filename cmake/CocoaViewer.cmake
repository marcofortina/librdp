# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_VIEWER AND APPLE)
    enable_language(OBJC)
    find_library(LIBRDP_COCOA_FRAMEWORK Cocoa REQUIRED)
    find_library(LIBRDP_AUDIOTOOLBOX_FRAMEWORK AudioToolbox REQUIRED)
    find_library(LIBRDP_AVFOUNDATION_FRAMEWORK AVFoundation REQUIRED)
    find_library(LIBRDP_COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
    find_library(LIBRDP_COREGRAPHICS_FRAMEWORK CoreGraphics REQUIRED)
    find_library(LIBRDP_COREMEDIA_FRAMEWORK CoreMedia REQUIRED)
    find_library(LIBRDP_COREVIDEO_FRAMEWORK CoreVideo REQUIRED)
    find_library(LIBRDP_IMAGEIO_FRAMEWORK ImageIO REQUIRED)
    add_executable(librdp-viewer
        apps/viewer/cocoa_cli.c
        apps/viewer/cocoa_session_loop.c
        apps/viewer/cocoa_main.m
        apps/viewer/cocoa_media.m
    )
    target_include_directories(librdp-viewer PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
    )
    target_link_libraries(librdp-viewer PRIVATE
        librdp_app_common
        ${LIBRDP_COCOA_FRAMEWORK}
        ${LIBRDP_AUDIOTOOLBOX_FRAMEWORK}
        ${LIBRDP_AVFOUNDATION_FRAMEWORK}
        ${LIBRDP_COREFOUNDATION_FRAMEWORK}
        ${LIBRDP_COREGRAPHICS_FRAMEWORK}
        ${LIBRDP_COREMEDIA_FRAMEWORK}
        ${LIBRDP_COREVIDEO_FRAMEWORK}
        ${LIBRDP_IMAGEIO_FRAMEWORK}
    )
    target_compile_options(librdp-viewer PRIVATE
        $<$<COMPILE_LANGUAGE:OBJC>:-fblocks>
    )
    librdp_apply_system_definitions(librdp-viewer)
    librdp_apply_warning_options(librdp-viewer)
    librdp_apply_sanitizer_compile_options(librdp-viewer)
    librdp_apply_sanitizer_link_options(librdp-viewer)
    install(TARGETS librdp-viewer
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    if(LIBRDP_BUILD_TESTS)
        add_executable(test_cocoa_media
            tests/test_cocoa_media.m
            apps/viewer/cocoa_cli.c
            apps/viewer/cocoa_media.m
        )
        target_include_directories(test_cocoa_media PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
        )
        target_link_libraries(test_cocoa_media PRIVATE
            librdp_app_common
            ${LIBRDP_COCOA_FRAMEWORK}
            ${LIBRDP_AUDIOTOOLBOX_FRAMEWORK}
            ${LIBRDP_AVFOUNDATION_FRAMEWORK}
            ${LIBRDP_COREFOUNDATION_FRAMEWORK}
            ${LIBRDP_COREGRAPHICS_FRAMEWORK}
            ${LIBRDP_COREMEDIA_FRAMEWORK}
            ${LIBRDP_COREVIDEO_FRAMEWORK}
            ${LIBRDP_IMAGEIO_FRAMEWORK}
        )
        target_compile_options(test_cocoa_media PRIVATE
            $<$<COMPILE_LANGUAGE:OBJC>:-fblocks>
        )
        librdp_apply_system_definitions(test_cocoa_media)
        librdp_apply_warning_options(test_cocoa_media)
        librdp_apply_sanitizer_compile_options(test_cocoa_media)
        librdp_apply_sanitizer_link_options(test_cocoa_media)
        add_test(NAME cocoa_media COMMAND test_cocoa_media)
        set_tests_properties(cocoa_media PROPERTIES TIMEOUT 30)
        add_test(NAME cocoa_viewer_cli COMMAND librdp-viewer --help)
        set_tests_properties(cocoa_viewer_cli PROPERTIES TIMEOUT 30)
    endif()
endif()
