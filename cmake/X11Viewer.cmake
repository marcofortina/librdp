# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_VIEWER AND NOT APPLE)
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
    pkg_check_modules(XKBCOMMON REQUIRED xkbcommon)
    add_executable(librdp-viewer
        apps/x11/viewer/audio_pipewire.c
        apps/x11/viewer/camera_v4l2.c
        apps/x11/viewer/device_backends.c
        apps/x11/viewer/main.c
        apps/x11/viewer/viewer_clipboard.c
        apps/x11/viewer/viewer_cli.c
        apps/x11/viewer/viewer_display.c
        apps/x11/viewer/viewer_input.c
        apps/x11/viewer/viewer_keyboard.c
        apps/x11/viewer/viewer_lifecycle.c
        apps/x11/viewer/viewer_render.c
        apps/x11/viewer/viewer_trace.c
        apps/x11/viewer/viewer_window.c
        apps/x11/x11_keymap.c
    )
    target_include_directories(librdp-viewer PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/viewer
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${X11_INCLUDE_DIR}
        ${XKBCOMMON_INCLUDE_DIRS}
    )
    target_link_libraries(librdp-viewer PRIVATE
        librdp_app_common
        Iconv::Iconv
        ${X11_LIBRARIES}
        X11::Xcursor
        X11::Xfixes
        ${XKBCOMMON_LIBRARIES}
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
        if(TARGET X11::Xext)
            target_link_libraries(librdp-viewer PRIVATE X11::Xext)
        else()
            target_link_libraries(librdp-viewer PRIVATE ${X11_Xext_LIB})
        endif()
    endif()
    if(LIBRDP_XRANDR_FOUND)
        target_compile_definitions(librdp-viewer PRIVATE LIBRDP_HAVE_XRANDR=1)
        if(TARGET X11::Xrandr)
            target_link_libraries(librdp-viewer PRIVATE X11::Xrandr)
        else()
            target_link_libraries(librdp-viewer PRIVATE ${X11_Xrandr_LIB})
        endif()
    endif()
    install(TARGETS librdp-viewer
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    if(LIBRDP_BUILD_TESTS)
        add_executable(test_viewer_render
            tests/test_viewer_render.c
            apps/x11/viewer/viewer_render.c
            apps/x11/viewer/viewer_trace.c
            apps/x11/viewer/viewer_window.c
        )
        target_include_directories(test_viewer_render PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/viewer
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${X11_INCLUDE_DIR}
        )
        librdp_apply_system_definitions(test_viewer_render)
        target_link_libraries(test_viewer_render PRIVATE librdp ${X11_LIBRARIES})
        if(LIBRDP_XSHM_FOUND)
            target_compile_definitions(test_viewer_render PRIVATE LIBRDP_HAVE_XSHM=1)
            if(TARGET X11::Xext)
                target_link_libraries(test_viewer_render PRIVATE X11::Xext)
            else()
                target_link_libraries(test_viewer_render PRIVATE ${X11_Xext_LIB})
            endif()
        endif()
        librdp_apply_warning_options(test_viewer_render)
        librdp_apply_sanitizer_compile_options(test_viewer_render)
        librdp_apply_sanitizer_link_options(test_viewer_render)
        add_test(NAME viewer_render COMMAND test_viewer_render)
        set_tests_properties(viewer_render PROPERTIES TIMEOUT 30)
        add_executable(test_viewer_audio
            tests/test_viewer_audio.c
            apps/x11/viewer/audio_pipewire.c
            apps/x11/viewer/viewer_trace.c
        )
        target_include_directories(test_viewer_audio PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/viewer
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_compile_definitions(test_viewer_audio PRIVATE
            LIBRDP_X11_AUDIO_TESTING=1
        )
        librdp_apply_system_definitions(test_viewer_audio)
        librdp_apply_warning_options(test_viewer_audio)
        librdp_apply_sanitizer_compile_options(test_viewer_audio)
        librdp_apply_sanitizer_link_options(test_viewer_audio)
        add_test(NAME viewer_audio COMMAND test_viewer_audio)
        set_tests_properties(viewer_audio PROPERTIES TIMEOUT 30)
        add_executable(test_viewer_camera
            tests/test_viewer_camera.c
            apps/x11/viewer/camera_v4l2.c
            apps/x11/viewer/viewer_trace.c
        )
        target_include_directories(test_viewer_camera PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/viewer
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_compile_definitions(test_viewer_camera PRIVATE
            LIBRDP_X11_CAMERA_TESTING=1
        )
        librdp_apply_system_definitions(test_viewer_camera)
        librdp_apply_x11_camera_backends(test_viewer_camera)
        librdp_apply_warning_options(test_viewer_camera)
        librdp_apply_sanitizer_compile_options(test_viewer_camera)
        librdp_apply_sanitizer_link_options(test_viewer_camera)
        add_test(NAME viewer_camera COMMAND test_viewer_camera)
        set_tests_properties(viewer_camera PROPERTIES TIMEOUT 30)
        add_executable(test_viewer_keyboard
            tests/test_viewer_keyboard.c
            apps/x11/x11_keymap.c
            apps/x11/viewer/viewer_keyboard.c
            apps/x11/viewer/viewer_trace.c
            apps/x11/viewer/viewer_window.c
        )
        target_include_directories(test_viewer_keyboard PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/viewer
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${X11_INCLUDE_DIR}
            ${XKBCOMMON_INCLUDE_DIRS}
        )
        librdp_apply_system_definitions(test_viewer_keyboard)
        target_link_libraries(test_viewer_keyboard PRIVATE
            librdp
            ${X11_LIBRARIES}
            ${XKBCOMMON_LIBRARIES}
        )
        librdp_apply_warning_options(test_viewer_keyboard)
        librdp_apply_sanitizer_compile_options(test_viewer_keyboard)
        librdp_apply_sanitizer_link_options(test_viewer_keyboard)
        add_test(NAME viewer_keyboard COMMAND test_viewer_keyboard)
        set_tests_properties(viewer_keyboard PROPERTIES TIMEOUT 30)
        add_executable(test_viewer_clipboard
            tests/test_viewer_clipboard.c
            apps/x11/viewer/viewer_clipboard.c
            apps/x11/viewer/viewer_trace.c
        )
        target_include_directories(test_viewer_clipboard PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/viewer
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${X11_INCLUDE_DIR}
        )
        librdp_apply_system_definitions(test_viewer_clipboard)
        target_link_libraries(test_viewer_clipboard PRIVATE
            librdp
            Iconv::Iconv
            ${X11_LIBRARIES}
            X11::Xfixes
        )
        librdp_apply_warning_options(test_viewer_clipboard)
        librdp_apply_sanitizer_compile_options(test_viewer_clipboard)
        librdp_apply_sanitizer_link_options(test_viewer_clipboard)
        add_test(NAME viewer_clipboard COMMAND test_viewer_clipboard)
        set_tests_properties(viewer_clipboard PROPERTIES TIMEOUT 30)
        if(LIBRDP_XRANDR_FOUND)
            add_executable(test_viewer_display
                tests/test_viewer_display.c
                apps/x11/viewer/viewer_display.c
                apps/x11/viewer/viewer_trace.c
            )
            target_include_directories(test_viewer_display PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/viewer
                ${CMAKE_CURRENT_SOURCE_DIR}/include
                ${X11_INCLUDE_DIR}
            )
            target_compile_definitions(test_viewer_display PRIVATE
                LIBRDP_HAVE_XRANDR=1
            )
            librdp_apply_system_definitions(test_viewer_display)
            target_link_libraries(test_viewer_display PRIVATE librdp ${X11_LIBRARIES})
            if(TARGET X11::Xrandr)
                target_link_libraries(test_viewer_display PRIVATE X11::Xrandr)
            else()
                target_link_libraries(test_viewer_display PRIVATE ${X11_Xrandr_LIB})
            endif()
            librdp_apply_warning_options(test_viewer_display)
            librdp_apply_sanitizer_compile_options(test_viewer_display)
            librdp_apply_sanitizer_link_options(test_viewer_display)
            add_test(NAME viewer_display COMMAND test_viewer_display)
            set_tests_properties(viewer_display PROPERTIES TIMEOUT 30)
        endif()
    endif()
endif()
