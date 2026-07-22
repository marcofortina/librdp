# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_TESTS OR LIBRDP_BUILD_VIEWER)
    add_library(librdp_viewer_common STATIC
        apps/viewer/client_callbacks.c
        apps/viewer/client_credentials.c
        apps/viewer/client_options.c
        apps/viewer/client_providers.c
        apps/viewer/client_runtime.c
        apps/viewer/client_tls.c
    )
    target_include_directories(librdp_viewer_common PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(librdp_viewer_common PUBLIC librdp)
    librdp_apply_system_definitions(librdp_viewer_common)
    librdp_apply_warning_options(librdp_viewer_common)
    librdp_apply_sanitizer_compile_options(librdp_viewer_common)
    librdp_apply_sanitizer_link_options(librdp_viewer_common)
endif()

if(LIBRDP_BUILD_VIEWER AND LIBRDP_NATIVE_APP_BACKEND STREQUAL "x11")
    find_package(X11 REQUIRED COMPONENTS Xcursor Xfixes)
    if(NOT "${LIBRDP_WITH_XSHM}" STREQUAL "OFF")
        find_package(X11 QUIET COMPONENTS Xext)
        if(X11_Xext_FOUND OR X11_Xext_LIB)
            set(LIBRDP_XSHM_FOUND 1 CACHE INTERNAL "MIT-SHM support found for the X11 viewer" FORCE)
        elseif("${LIBRDP_WITH_XSHM}" STREQUAL "ON")
            message(FATAL_ERROR "LIBRDP_WITH_XSHM=ON requires Xext")
        endif()
    endif()
    if(NOT "${LIBRDP_WITH_XRANDR}" STREQUAL "OFF")
        find_package(X11 QUIET COMPONENTS Xrandr)
        if(X11_Xrandr_FOUND OR X11_Xrandr_LIB)
            set(LIBRDP_XRANDR_FOUND 1 CACHE INTERNAL "XRandR support found for the X11 viewer" FORCE)
        elseif("${LIBRDP_WITH_XRANDR}" STREQUAL "ON")
            message(FATAL_ERROR "LIBRDP_WITH_XRANDR=ON requires Xrandr")
        endif()
    endif()
    find_package(PkgConfig REQUIRED)
    find_package(Threads REQUIRED)
    pkg_check_modules(
        LIBRDP_XKBCOMMON REQUIRED IMPORTED_TARGET xkbcommon)
    set(LIBRDP_X11_LINK_BASE X11::X11)
    set(LIBRDP_X11_LINK_CURSOR X11::Xcursor)
    set(LIBRDP_X11_LINK_FIXES X11::Xfixes)
    set(LIBRDP_X11_LINK_EXT X11::Xext)
    set(LIBRDP_X11_LINK_RANDR X11::Xrandr)
    if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
        # FindX11 extension targets repeat their base libraries on Solaris.
        set(LIBRDP_X11_LINK_BASE ${X11_X11_LIB})
        set(LIBRDP_X11_LINK_CURSOR ${X11_Xcursor_LIB})
        set(LIBRDP_X11_LINK_FIXES ${X11_Xfixes_LIB})
        set(LIBRDP_X11_LINK_EXT ${X11_Xext_LIB})
        set(LIBRDP_X11_LINK_RANDR ${X11_Xrandr_LIB})
    endif()
    add_executable(librdp-viewer
        apps/viewer/x11_audio_pipewire.c
        apps/viewer/x11_camera_v4l2.c
        apps/viewer/x11_device_backends.c
        apps/viewer/x11_main.c
        apps/viewer/x11_clipboard.c
        apps/viewer/x11_cli.c
        apps/viewer/x11_display.c
        apps/viewer/x11_input.c
        apps/viewer/x11_keyboard.c
        apps/viewer/x11_lifecycle.c
        apps/viewer/x11_render.c
        apps/viewer/x11_trace.c
        apps/viewer/x11_window.c
        apps/common/x11_keymap.c
    )
    librdp_set_application_backend(librdp-viewer x11)
    target_include_directories(librdp-viewer PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${X11_INCLUDE_DIR}
    )
    target_link_libraries(librdp-viewer PRIVATE
        librdp_viewer_common
        Iconv::Iconv
        ${LIBRDP_X11_LINK_BASE}
        ${LIBRDP_X11_LINK_CURSOR}
        ${LIBRDP_X11_LINK_FIXES}
        PkgConfig::LIBRDP_XKBCOMMON
        Threads::Threads
    )
    librdp_apply_system_definitions(librdp-viewer)
    get_target_property(LIBRDP_X11_VIEWER_INCLUDES librdp-viewer INCLUDE_DIRECTORIES)
    foreach(LIBRDP_X11_VIEWER_INCLUDE IN LISTS LIBRDP_X11_VIEWER_INCLUDES)
        if(NOT IS_ABSOLUTE "${LIBRDP_X11_VIEWER_INCLUDE}")
            continue()
        endif()
        file(REAL_PATH "${LIBRDP_X11_VIEWER_INCLUDE}" LIBRDP_X11_VIEWER_INCLUDE_REAL)
        file(REAL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src" LIBRDP_SOURCE_PRIVATE_INCLUDE_REAL)
        string(FIND "${LIBRDP_X11_VIEWER_INCLUDE_REAL}/"
            "${LIBRDP_SOURCE_PRIVATE_INCLUDE_REAL}/" LIBRDP_X11_VIEWER_PRIVATE_INCLUDE_INDEX)
        if(LIBRDP_X11_VIEWER_PRIVATE_INCLUDE_INDEX EQUAL 0)
            message(FATAL_ERROR "librdp-viewer must not include private src headers")
        endif()
    endforeach()
    librdp_apply_warning_options(librdp-viewer)
    librdp_apply_sanitizer_compile_options(librdp-viewer)
    librdp_apply_sanitizer_link_options(librdp-viewer)
    if(LIBRDP_PIPEWIRE_FOUND)
        target_compile_definitions(librdp-viewer PRIVATE LIBRDP_HAVE_PIPEWIRE=1)
        target_link_libraries(librdp-viewer PRIVATE PkgConfig::LIBRDP_PIPEWIRE)
    endif()
    librdp_apply_x11_device_backends(librdp-viewer)
    librdp_apply_x11_camera_backends(librdp-viewer)
    if(LIBRDP_XSHM_FOUND)
        target_compile_definitions(librdp-viewer PRIVATE LIBRDP_HAVE_XSHM=1)
        target_link_libraries(librdp-viewer PRIVATE ${LIBRDP_X11_LINK_EXT})
    endif()
    if(LIBRDP_XRANDR_FOUND)
        target_compile_definitions(librdp-viewer PRIVATE LIBRDP_HAVE_XRANDR=1)
        target_link_libraries(librdp-viewer PRIVATE ${LIBRDP_X11_LINK_RANDR})
    endif()
    install(TARGETS librdp-viewer
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    if(LIBRDP_BUILD_TESTS)
        add_test(NAME viewer_cli COMMAND librdp-viewer --help)
        set_tests_properties(viewer_cli PROPERTIES TIMEOUT 30)

        add_executable(test_x11_viewer_backends
            tests/test_x11_viewer_backends.c
            apps/viewer/x11_camera_v4l2.c
            apps/viewer/x11_device_backends.c
            apps/viewer/x11_trace.c
        )
        target_include_directories(test_x11_viewer_backends PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        librdp_apply_system_definitions(test_x11_viewer_backends)
        target_link_libraries(test_x11_viewer_backends PRIVATE librdp)
        librdp_apply_x11_camera_backends(test_x11_viewer_backends)
        librdp_apply_x11_device_backends(test_x11_viewer_backends)
        librdp_apply_warning_options(test_x11_viewer_backends)
        librdp_apply_sanitizer_compile_options(test_x11_viewer_backends)
        librdp_apply_sanitizer_link_options(test_x11_viewer_backends)
        add_test(NAME x11_viewer_backends COMMAND test_x11_viewer_backends)
        set_tests_properties(x11_viewer_backends PROPERTIES TIMEOUT 30)

        add_executable(test_x11_viewer_cli
            tests/test_x11_viewer_cli.c
            apps/viewer/x11_cli.c
            apps/viewer/x11_trace.c
        )
        target_include_directories(test_x11_viewer_cli PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        librdp_apply_system_definitions(test_x11_viewer_cli)
        target_link_libraries(test_x11_viewer_cli PRIVATE
            librdp_viewer_common
        )
        librdp_apply_warning_options(test_x11_viewer_cli)
        librdp_apply_sanitizer_compile_options(test_x11_viewer_cli)
        librdp_apply_sanitizer_link_options(test_x11_viewer_cli)
        add_test(NAME x11_viewer_cli COMMAND test_x11_viewer_cli)
        set_tests_properties(x11_viewer_cli PROPERTIES TIMEOUT 30)

        add_executable(test_x11_viewer_render
            tests/test_x11_viewer_render.c
            apps/viewer/x11_render.c
            apps/viewer/x11_trace.c
            apps/viewer/x11_window.c
        )
        target_include_directories(test_x11_viewer_render PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${X11_INCLUDE_DIR}
        )
        librdp_apply_system_definitions(test_x11_viewer_render)
        target_link_libraries(test_x11_viewer_render PRIVATE
            librdp
            ${LIBRDP_X11_LINK_BASE}
        )
        if(LIBRDP_XSHM_FOUND)
            target_compile_definitions(test_x11_viewer_render PRIVATE LIBRDP_HAVE_XSHM=1)
            target_link_libraries(test_x11_viewer_render PRIVATE
                ${LIBRDP_X11_LINK_EXT}
            )
        endif()
        find_program(LIBRDP_VIEWER_XVFB_EXECUTABLE NAMES Xvfb)
        if(LIBRDP_VIEWER_XVFB_EXECUTABLE)
            target_compile_definitions(test_x11_viewer_render PRIVATE
                LIBRDP_TEST_XVFB_PATH="${LIBRDP_VIEWER_XVFB_EXECUTABLE}"
            )
            if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
                target_compile_definitions(test_x11_viewer_render PRIVATE
                    LIBRDP_TEST_XVFB_EXPLICIT_DISPLAY=1
                )
            endif()
        endif()
        librdp_apply_warning_options(test_x11_viewer_render)
        librdp_apply_sanitizer_compile_options(test_x11_viewer_render)
        librdp_apply_sanitizer_link_options(test_x11_viewer_render)
        add_test(NAME x11_viewer_render COMMAND test_x11_viewer_render)
        set_tests_properties(x11_viewer_render PROPERTIES TIMEOUT 30)
        add_executable(test_x11_viewer_audio
            tests/test_x11_viewer_audio.c
            apps/viewer/x11_audio_pipewire.c
            apps/viewer/x11_trace.c
        )
        target_include_directories(test_x11_viewer_audio PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_compile_definitions(test_x11_viewer_audio PRIVATE
            LIBRDP_X11_AUDIO_TESTING=1
        )
        librdp_apply_system_definitions(test_x11_viewer_audio)
        librdp_apply_warning_options(test_x11_viewer_audio)
        librdp_apply_sanitizer_compile_options(test_x11_viewer_audio)
        librdp_apply_sanitizer_link_options(test_x11_viewer_audio)
        add_test(NAME x11_viewer_audio COMMAND test_x11_viewer_audio)
        set_tests_properties(x11_viewer_audio PROPERTIES TIMEOUT 30)
        if(LIBRDP_PIPEWIRE_FOUND)
            add_executable(test_x11_pipewire_live_smoke
                tests/test_x11_pipewire_live_smoke.c
                apps/viewer/x11_audio_pipewire.c
                apps/viewer/x11_trace.c
            )
            target_include_directories(test_x11_pipewire_live_smoke PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
                ${CMAKE_CURRENT_SOURCE_DIR}/include
            )
            target_compile_definitions(test_x11_pipewire_live_smoke PRIVATE
                LIBRDP_HAVE_PIPEWIRE=1
            )
            target_link_libraries(test_x11_pipewire_live_smoke PRIVATE
                PkgConfig::LIBRDP_PIPEWIRE
                Threads::Threads
            )
            librdp_apply_system_definitions(test_x11_pipewire_live_smoke)
            librdp_apply_warning_options(test_x11_pipewire_live_smoke)
            librdp_apply_sanitizer_compile_options(test_x11_pipewire_live_smoke)
            librdp_apply_sanitizer_link_options(test_x11_pipewire_live_smoke)
            add_test(NAME x11_pipewire_live_smoke
                     COMMAND test_x11_pipewire_live_smoke)
            set_tests_properties(x11_pipewire_live_smoke PROPERTIES
                SKIP_RETURN_CODE 77
                TIMEOUT 30
            )
        endif()
        add_executable(test_x11_viewer_camera
            tests/test_x11_viewer_camera.c
            apps/viewer/x11_camera_v4l2.c
            apps/viewer/x11_trace.c
        )
        target_include_directories(test_x11_viewer_camera PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_compile_definitions(test_x11_viewer_camera PRIVATE
            LIBRDP_X11_CAMERA_TESTING=1
        )
        librdp_apply_system_definitions(test_x11_viewer_camera)
        librdp_apply_x11_camera_backends(test_x11_viewer_camera)
        librdp_apply_warning_options(test_x11_viewer_camera)
        librdp_apply_sanitizer_compile_options(test_x11_viewer_camera)
        librdp_apply_sanitizer_link_options(test_x11_viewer_camera)
        add_test(NAME x11_viewer_camera COMMAND test_x11_viewer_camera)
        set_tests_properties(x11_viewer_camera PROPERTIES TIMEOUT 30)
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            add_executable(test_x11_camera_live_smoke
                tests/test_x11_camera_live_smoke.c
                apps/viewer/x11_camera_v4l2.c
                apps/viewer/x11_trace.c
            )
            target_include_directories(test_x11_camera_live_smoke PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
                ${CMAKE_CURRENT_SOURCE_DIR}/include
            )
            librdp_apply_system_definitions(test_x11_camera_live_smoke)
            librdp_apply_x11_camera_backends(test_x11_camera_live_smoke)
            librdp_apply_warning_options(test_x11_camera_live_smoke)
            librdp_apply_sanitizer_compile_options(test_x11_camera_live_smoke)
            librdp_apply_sanitizer_link_options(test_x11_camera_live_smoke)
            add_test(NAME x11_camera_live_smoke COMMAND test_x11_camera_live_smoke)
            set_tests_properties(x11_camera_live_smoke PROPERTIES
                SKIP_RETURN_CODE 77
                TIMEOUT 30
            )
        endif()
        add_executable(test_x11_viewer_keyboard
            tests/test_x11_viewer_keyboard.c
            apps/common/x11_keymap.c
            apps/viewer/x11_keyboard.c
            apps/viewer/x11_trace.c
            apps/viewer/x11_window.c
        )
        target_include_directories(test_x11_viewer_keyboard PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${X11_INCLUDE_DIR}
        )
        librdp_apply_system_definitions(test_x11_viewer_keyboard)
        target_link_libraries(test_x11_viewer_keyboard PRIVATE
            librdp
            ${LIBRDP_X11_LINK_BASE}
            PkgConfig::LIBRDP_XKBCOMMON
        )
        librdp_apply_warning_options(test_x11_viewer_keyboard)
        librdp_apply_sanitizer_compile_options(test_x11_viewer_keyboard)
        librdp_apply_sanitizer_link_options(test_x11_viewer_keyboard)
        add_test(NAME x11_viewer_keyboard COMMAND test_x11_viewer_keyboard)
        set_tests_properties(x11_viewer_keyboard PROPERTIES TIMEOUT 30)
        add_executable(test_x11_viewer_clipboard
            tests/test_x11_viewer_clipboard.c
            apps/viewer/x11_clipboard.c
            apps/viewer/x11_trace.c
        )
        target_include_directories(test_x11_viewer_clipboard PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${X11_INCLUDE_DIR}
        )
        librdp_apply_system_definitions(test_x11_viewer_clipboard)
        target_link_libraries(test_x11_viewer_clipboard PRIVATE
            librdp
            Iconv::Iconv
            ${LIBRDP_X11_LINK_BASE}
            ${LIBRDP_X11_LINK_FIXES}
        )
        librdp_apply_warning_options(test_x11_viewer_clipboard)
        librdp_apply_sanitizer_compile_options(test_x11_viewer_clipboard)
        librdp_apply_sanitizer_link_options(test_x11_viewer_clipboard)
        add_test(NAME x11_viewer_clipboard COMMAND test_x11_viewer_clipboard)
        set_tests_properties(x11_viewer_clipboard PROPERTIES TIMEOUT 30)
        if(LIBRDP_XRANDR_FOUND)
            add_executable(test_x11_viewer_display
                tests/test_x11_viewer_display.c
                apps/viewer/x11_display.c
                apps/viewer/x11_trace.c
            )
            target_include_directories(test_x11_viewer_display PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
                ${CMAKE_CURRENT_SOURCE_DIR}/include
                ${X11_INCLUDE_DIR}
            )
            target_compile_definitions(test_x11_viewer_display PRIVATE
                LIBRDP_HAVE_XRANDR=1
            )
            librdp_apply_system_definitions(test_x11_viewer_display)
            target_link_libraries(test_x11_viewer_display PRIVATE
                librdp
                ${LIBRDP_X11_LINK_BASE}
                ${LIBRDP_X11_LINK_RANDR}
            )
            librdp_apply_warning_options(test_x11_viewer_display)
            librdp_apply_sanitizer_compile_options(test_x11_viewer_display)
            librdp_apply_sanitizer_link_options(test_x11_viewer_display)
            add_test(NAME x11_viewer_display COMMAND test_x11_viewer_display)
            set_tests_properties(x11_viewer_display PROPERTIES TIMEOUT 30)
        endif()
    endif()
endif()

if(LIBRDP_BUILD_VIEWER AND LIBRDP_NATIVE_APP_BACKEND STREQUAL "cocoa")
    enable_language(OBJC)
    find_library(LIBRDP_VIEWER_COCOA_FRAMEWORK Cocoa REQUIRED)
    find_library(LIBRDP_VIEWER_AUDIOTOOLBOX_FRAMEWORK AudioToolbox REQUIRED)
    find_library(LIBRDP_VIEWER_AVFOUNDATION_FRAMEWORK AVFoundation REQUIRED)
    find_library(LIBRDP_VIEWER_CARBON_FRAMEWORK Carbon REQUIRED)
    find_library(LIBRDP_VIEWER_COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
    find_library(LIBRDP_VIEWER_COREGRAPHICS_FRAMEWORK CoreGraphics REQUIRED)
    find_library(LIBRDP_VIEWER_COREMEDIA_FRAMEWORK CoreMedia REQUIRED)
    find_library(LIBRDP_VIEWER_COREVIDEO_FRAMEWORK CoreVideo REQUIRED)
    find_library(LIBRDP_VIEWER_IMAGEIO_FRAMEWORK ImageIO REQUIRED)
    add_executable(librdp-viewer
        apps/common/cocoa_keymap.c
        apps/viewer/cocoa_cli.c
        apps/viewer/cocoa_clipboard.m
        apps/viewer/cocoa_input.m
        apps/viewer/cocoa_session_loop.c
        apps/viewer/cocoa_main.m
        apps/viewer/cocoa_media.m
        apps/viewer/cocoa_render.m
    )
    librdp_set_application_backend(librdp-viewer cocoa)
    target_include_directories(librdp-viewer PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
    )
    target_link_libraries(librdp-viewer PRIVATE
        librdp_viewer_common
        ${LIBRDP_VIEWER_COCOA_FRAMEWORK}
        ${LIBRDP_VIEWER_AUDIOTOOLBOX_FRAMEWORK}
        ${LIBRDP_VIEWER_AVFOUNDATION_FRAMEWORK}
        ${LIBRDP_VIEWER_CARBON_FRAMEWORK}
        ${LIBRDP_VIEWER_COREFOUNDATION_FRAMEWORK}
        ${LIBRDP_VIEWER_COREGRAPHICS_FRAMEWORK}
        ${LIBRDP_VIEWER_COREMEDIA_FRAMEWORK}
        ${LIBRDP_VIEWER_COREVIDEO_FRAMEWORK}
        ${LIBRDP_VIEWER_IMAGEIO_FRAMEWORK}
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
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
        )
        target_link_libraries(test_cocoa_media PRIVATE
            librdp_viewer_common
            ${LIBRDP_VIEWER_COCOA_FRAMEWORK}
            ${LIBRDP_VIEWER_AUDIOTOOLBOX_FRAMEWORK}
            ${LIBRDP_VIEWER_AVFOUNDATION_FRAMEWORK}
            ${LIBRDP_VIEWER_COREFOUNDATION_FRAMEWORK}
            ${LIBRDP_VIEWER_COREGRAPHICS_FRAMEWORK}
            ${LIBRDP_VIEWER_COREMEDIA_FRAMEWORK}
            ${LIBRDP_VIEWER_COREVIDEO_FRAMEWORK}
            ${LIBRDP_VIEWER_IMAGEIO_FRAMEWORK}
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
        add_executable(test_cocoa_viewer_render
            tests/test_cocoa_viewer_render.m
            apps/viewer/cocoa_render.m
        )
        target_include_directories(test_cocoa_viewer_render PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
        )
        target_link_libraries(test_cocoa_viewer_render PRIVATE
            librdp
            ${LIBRDP_VIEWER_COREGRAPHICS_FRAMEWORK}
        )
        librdp_apply_system_definitions(test_cocoa_viewer_render)
        librdp_apply_warning_options(test_cocoa_viewer_render)
        librdp_apply_sanitizer_compile_options(test_cocoa_viewer_render)
        librdp_apply_sanitizer_link_options(test_cocoa_viewer_render)
        add_test(NAME cocoa_viewer_render
            COMMAND test_cocoa_viewer_render)
        set_tests_properties(cocoa_viewer_render PROPERTIES TIMEOUT 30)
        add_executable(test_cocoa_viewer_input
            tests/test_cocoa_viewer_input.m
            apps/common/cocoa_keymap.c
            apps/viewer/cocoa_input.m
        )
        target_include_directories(test_cocoa_viewer_input PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
        )
        target_link_libraries(test_cocoa_viewer_input PRIVATE
            librdp
            ${LIBRDP_VIEWER_COCOA_FRAMEWORK}
            ${LIBRDP_VIEWER_CARBON_FRAMEWORK}
        )
        librdp_apply_system_definitions(test_cocoa_viewer_input)
        librdp_apply_warning_options(test_cocoa_viewer_input)
        librdp_apply_sanitizer_compile_options(test_cocoa_viewer_input)
        librdp_apply_sanitizer_link_options(test_cocoa_viewer_input)
        add_test(NAME cocoa_viewer_input
            COMMAND test_cocoa_viewer_input)
        set_tests_properties(cocoa_viewer_input PROPERTIES TIMEOUT 30)
        add_executable(test_cocoa_viewer_clipboard
            tests/test_cocoa_viewer_clipboard.m
            apps/viewer/cocoa_clipboard.m
        )
        target_include_directories(test_cocoa_viewer_clipboard PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
        )
        target_link_libraries(test_cocoa_viewer_clipboard PRIVATE
            librdp
            ${LIBRDP_VIEWER_COCOA_FRAMEWORK}
        )
        librdp_apply_system_definitions(test_cocoa_viewer_clipboard)
        librdp_apply_warning_options(test_cocoa_viewer_clipboard)
        librdp_apply_sanitizer_compile_options(test_cocoa_viewer_clipboard)
        librdp_apply_sanitizer_link_options(test_cocoa_viewer_clipboard)
        add_test(NAME cocoa_viewer_clipboard
            COMMAND test_cocoa_viewer_clipboard)
        set_tests_properties(cocoa_viewer_clipboard PROPERTIES TIMEOUT 30)
        add_test(NAME viewer_cli COMMAND librdp-viewer --help)
        set_tests_properties(viewer_cli PROPERTIES TIMEOUT 30)
    endif()
endif()
