# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_TESTS)
    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND AND
       TARGET librdp-session-broker AND
       TARGET librdp-session-agent AND
       TARGET librdp-session-supervisor)
        set(LIBRDP_APP_INSTALL_LAYOUT_ARGUMENTS)
        foreach(application IN ITEMS
                librdp-admin
                librdp-server
                librdp-viewer
                librdp-workspace)
            if(TARGET ${application})
                list(APPEND
                    LIBRDP_APP_INSTALL_LAYOUT_ARGUMENTS
                    --application ${application})
            endif()
        endforeach()
        add_test(NAME app_install_layout
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_app_install_layout.py
                --cmake ${CMAKE_COMMAND}
                --build-dir ${CMAKE_CURRENT_BINARY_DIR}
                --destdir ${CMAKE_CURRENT_BINARY_DIR}/app-install-layout
                --bindir ${CMAKE_INSTALL_FULL_BINDIR}
                --sbindir ${CMAKE_INSTALL_FULL_SBINDIR}
                --libexecdir ${LIBRDP_X11_SESSION_LIBEXEC_DIR}
                --datadir ${CMAKE_INSTALL_FULL_DATADIR}/librdp
                --mandir ${CMAKE_INSTALL_FULL_MANDIR}
                ${LIBRDP_APP_INSTALL_LAYOUT_ARGUMENTS}
                --config $<CONFIG>
        )
        set_tests_properties(app_install_layout PROPERTIES
            RUN_SERIAL TRUE
            TIMEOUT 60
        )
    endif()
    set(LIBRDP_NESTED_CONFIGURE_ARGS)
    if(DEFINED OpenSSL_DIR AND NOT "${OpenSSL_DIR}" STREQUAL "")
        list(APPEND LIBRDP_NESTED_CONFIGURE_ARGS
            "-DLIBRDP_OPENSSL_DIR=${OpenSSL_DIR}"
        )
    endif()
    if(DEFINED OPENSSL_ROOT_DIR AND NOT "${OPENSSL_ROOT_DIR}" STREQUAL "")
        list(APPEND LIBRDP_NESTED_CONFIGURE_ARGS
            "-DLIBRDP_OPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}"
        )
    endif()
    if(LIBRDP_OPENSSL_INCLUDE_DIR)
        list(APPEND LIBRDP_NESTED_CONFIGURE_ARGS
            "-DLIBRDP_OPENSSL_INCLUDE_DIR=${LIBRDP_OPENSSL_INCLUDE_DIR}"
        )
    endif()
    function(librdp_configure_test_compile target)
        target_include_directories(${target} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/src
        )
        librdp_apply_system_definitions(${target})
        librdp_apply_openssl_include_dirs(${target})
        librdp_apply_warning_options(${target})
        librdp_apply_sanitizer_compile_options(${target})
        if(LIBRDP_FFMPEG_AVC_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_FFMPEG_AVC=1)
        endif()
        if(LIBRDP_OPENH264_AVC_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_OPENH264_AVC=1)
        endif()
        if(LIBRDP_LIBUSB_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_LIBUSB=1)
            target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_LIBUSB)
        endif()
        if(LIBRDP_PCSC_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_PCSC=1)
            target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_PCSC)
        endif()
        if(LIBRDP_CURL_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_CURL=1)
        endif()
        if(LIBRDP_ATTR_FOUND AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
            target_compile_definitions(${target} PRIVATE RDP_HAVE_ATTR=1)
        endif()
        if(LIBRDP_LIBXML2_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_LIBXML2=1)
        endif()
        if(LIBRDP_CAIRO_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_CAIRO=1)
        endif()
        if(LIBRDP_PNG_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_PNG=1)
        endif()
        if(LIBRDP_JPEG_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_JPEG=1)
        endif()
        if(LIBRDP_QUARTZ_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_QUARTZ=1)
        endif()
    endfunction()

    function(librdp_configure_test_executable target)
        librdp_configure_test_compile(${target})
        librdp_link_internal_runtime(${target})
        librdp_apply_sanitizer_link_options(${target})
    endfunction()

    add_library(test_core_units OBJECT
        tests/test_core.c
        tests/test_core_channels.c
        tests/test_core_common.c
        tests/test_core_enterprise.c
        tests/test_core_features.c
        tests/test_core_faults.c
        tests/test_core_graphics.c
        tests/test_core_limits.c
        tests/test_core_licensing.c
        tests/test_core_settings.c
        tests/test_core_storage.c
        tests/test_core_support.c
    )
    target_compile_definitions(test_core_units PRIVATE LIBRDP_TEST_NO_MAIN)
    target_compile_definitions(test_core_units PRIVATE RDP_ENABLE_TEST_FAULTS=1)
    librdp_configure_test_compile(test_core_units)

    add_library(test_core_device_units OBJECT tests/test_core_devices.c)
    target_compile_definitions(test_core_device_units PRIVATE LIBRDP_TEST_NO_MAIN)
    librdp_configure_test_compile(test_core_device_units)

    add_executable(test_common
        tests/test_common_main.c
        $<TARGET_OBJECTS:test_core_units>
        $<TARGET_OBJECTS:test_core_device_units>
    )
    librdp_configure_test_executable(test_common)

    add_executable(test_core
        tests/test_core_main.c
        $<TARGET_OBJECTS:test_core_units>
        $<TARGET_OBJECTS:test_core_device_units>
    )
    librdp_configure_test_executable(test_core)

    add_executable(test_protocol
        tests/test_protocol.c
        tests/test_protocol_activation.c
        tests/test_protocol_authentication.c
        tests/test_protocol_channels.c
        tests/test_protocol_clipboard.c
        tests/test_protocol_codecs.c
        tests/test_protocol_core.c
        tests/test_protocol_devices.c
        tests/test_protocol_graphics.c
        tests/test_protocol_graphics_pipeline.c
        tests/test_protocol_interaction.c
        tests/test_protocol_security.c
        tests/test_protocol_transport.c
        tests/test_protocol_updates.c
    )
    target_compile_definitions(test_protocol PRIVATE LIBRDP_TEST_PROTOCOL_MAIN)
    librdp_configure_test_executable(test_protocol)

    add_executable(test_transport tests/test_transport.c)
    target_compile_definitions(test_transport PRIVATE LIBRDP_TEST_TRANSPORT_MAIN)
    librdp_configure_test_executable(test_transport)

    add_executable(test_server
        tests/test_server.c
        tests/test_server_config.c
        tests/test_server_features.c
        tests/test_server_focused.c
        tests/test_server_runtime.c
        tests/test_server_security.c
        tests/test_server_support.c
    )
    librdp_configure_test_executable(test_server)

    add_executable(test_interop_smoke tests/interop_smoke.c)
    target_include_directories(test_interop_smoke PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(test_interop_smoke PRIVATE librdp)
    librdp_apply_warning_options(test_interop_smoke)
    librdp_apply_sanitizer_compile_options(test_interop_smoke)
    librdp_apply_sanitizer_link_options(test_interop_smoke)

    add_executable(test_optional_backend_probe tests/optional_backend_probe.c)
    librdp_configure_test_executable(test_optional_backend_probe)

    add_executable(test_viewer_common tests/test_viewer_common.c)
    target_include_directories(test_viewer_common PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(test_viewer_common PRIVATE librdp_viewer_common)
    librdp_apply_system_definitions(test_viewer_common)
    librdp_apply_warning_options(test_viewer_common)
    librdp_apply_sanitizer_compile_options(test_viewer_common)
    librdp_apply_sanitizer_link_options(test_viewer_common)

    add_executable(test_admin_workspace tests/test_admin_workspace.c)
    target_include_directories(test_admin_workspace PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/admin
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/workspace
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(test_admin_workspace PRIVATE
        librdp_admin_common
        librdp_workspace_common
    )
    librdp_apply_system_definitions(test_admin_workspace)
    if(LIBRDP_LIBXML2_FOUND)
        target_compile_definitions(test_admin_workspace PRIVATE
            RDP_HAVE_LIBXML2=1
        )
    endif()
    librdp_apply_warning_options(test_admin_workspace)
    librdp_apply_sanitizer_compile_options(test_admin_workspace)
    librdp_apply_sanitizer_link_options(test_admin_workspace)

    add_executable(test_server_host tests/test_server_host.c)
    target_include_directories(test_server_host PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(test_server_host PRIVATE librdp_server_common)
    librdp_apply_system_definitions(test_server_host)
    librdp_apply_warning_options(test_server_host)
    librdp_apply_sanitizer_compile_options(test_server_host)
    librdp_apply_sanitizer_link_options(test_server_host)

    add_executable(test_server_host_drive tests/test_server_host_drive.c)
    target_include_directories(test_server_host_drive PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(test_server_host_drive PRIVATE librdp_server_common)
    librdp_apply_system_definitions(test_server_host_drive)
    librdp_apply_warning_options(test_server_host_drive)
    librdp_apply_sanitizer_compile_options(test_server_host_drive)
    librdp_apply_sanitizer_link_options(test_server_host_drive)

    add_executable(test_server_client_smoke
        tests/test_server_client_clipboard.c
        tests/test_server_client_smoke.c
        tests/test_http_proxy.c
        tests/test_process_state.c
        tests/test_rdg_gateway.c
        tests/test_server_support.c
    )
    target_include_directories(test_server_client_smoke PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )
    target_link_libraries(test_server_client_smoke PRIVATE
        "$<TARGET_FILE:librdp_server_common>"
        "$<TARGET_FILE:librdp_viewer_common>"
    )
    add_dependencies(test_server_client_smoke
        librdp_server_common
        librdp_viewer_common
    )
    librdp_configure_test_executable(test_server_client_smoke)
    add_executable(test_server_client_input_smoke
        tests/test_server_client_input_smoke.c
    )
    librdp_configure_test_executable(
        test_server_client_input_smoke
    )
    add_executable(test_server_client_port_smoke
        tests/test_server_client_port_smoke.c
    )
    librdp_configure_test_executable(
        test_server_client_port_smoke
    )
    add_executable(test_pnp_virtual_smoke
        tests/test_pnp_virtual_smoke.c
    )
    librdp_configure_test_executable(test_pnp_virtual_smoke)
    add_executable(test_audio_virtual_smoke
        tests/test_audio_virtual_smoke.c
    )
    librdp_configure_test_executable(test_audio_virtual_smoke)
    add_executable(test_video_virtual_smoke
        tests/test_video_virtual_smoke.c
    )
    librdp_configure_test_executable(test_video_virtual_smoke)
    if(LIBRDP_CUPS_FOUND)
        add_executable(test_printer_cups_smoke
            tests/test_printer_cups_smoke.c
        )
        librdp_configure_test_executable(test_printer_cups_smoke)
    endif()
    if(LIBRDP_PCSC_FOUND)
        add_executable(test_smartcard_pcsc_smoke
            tests/test_smartcard_pcsc_smoke.c
        )
        librdp_configure_test_executable(test_smartcard_pcsc_smoke)
    endif()
    if(LIBRDP_LIBUSB_FOUND)
        add_executable(test_usb_virtual_smoke
            tests/test_usb_virtual_smoke.c
        )
        librdp_configure_test_executable(test_usb_virtual_smoke)
    endif()
    if(TARGET librdp-viewer AND
       LIBRDP_NATIVE_APP_BACKEND STREQUAL "x11")
        find_program(LIBRDP_VIEWER_SMOKE_XVFB_EXECUTABLE NAMES Xvfb)
        find_package(X11 QUIET COMPONENTS Xtst)
        if(LIBRDP_VIEWER_SMOKE_XVFB_EXECUTABLE AND
           X11_Xtst_INCLUDE_PATH AND
           X11_Xtst_LIB)
            add_executable(test_viewer_pointer_server
                tests/test_process_state.c
                tests/test_viewer_pointer_server.c
            )
            target_include_directories(
                test_viewer_pointer_server
                PRIVATE
                    ${CMAKE_CURRENT_SOURCE_DIR}/tests
            )
            librdp_configure_test_executable(
                test_viewer_pointer_server
            )
            add_executable(test_x11_viewer_presentation_smoke
                tests/test_process_state.c
                tests/test_x11_viewer_presentation_smoke.c
            )
            target_include_directories(
                test_x11_viewer_presentation_smoke
                PRIVATE
                    ${X11_INCLUDE_DIR}
                    ${X11_Xtst_INCLUDE_PATH}
            )
            target_compile_definitions(
                test_x11_viewer_presentation_smoke
                PRIVATE
                    LIBRDP_TEST_XVFB_PATH="${LIBRDP_VIEWER_SMOKE_XVFB_EXECUTABLE}"
                    LIBRDP_TEST_VIEWER_PATH="$<TARGET_FILE:librdp-viewer>"
                    LIBRDP_TEST_GRAPHICS_SERVER_PATH="$<TARGET_FILE:test_server_client_smoke>"
                    LIBRDP_TEST_POINTER_SERVER_PATH="$<TARGET_FILE:test_viewer_pointer_server>"
            )
            if(LIBRDP_FFMPEG_AVC_FOUND OR
               LIBRDP_OPENH264_AVC_FOUND)
                target_compile_definitions(
                    test_x11_viewer_presentation_smoke
                    PRIVATE LIBRDP_TEST_HAVE_AVC=1
                )
            endif()
            target_link_libraries(
                test_x11_viewer_presentation_smoke
                PRIVATE
                    OpenSSL::Crypto
                    ${X11_LIBRARIES}
                    X11::Xfixes
                    ${X11_Xtst_LIB}
            )
            add_dependencies(
                test_x11_viewer_presentation_smoke
                librdp-viewer
                test_server_client_smoke
                test_viewer_pointer_server
            )
            librdp_configure_test_executable(
                test_x11_viewer_presentation_smoke
            )
        endif()
    endif()

    if(TARGET librdp-workspace AND
       LIBRDP_CURL_FOUND AND
       LIBRDP_LIBXML2_FOUND)
        add_executable(test_workspace_launch_smoke
            tests/test_workspace_launch_smoke.c
        )
        target_include_directories(test_workspace_launch_smoke PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
        )
        target_link_libraries(test_workspace_launch_smoke PRIVATE
            "$<TARGET_FILE:librdp_server_common>"
            "$<TARGET_FILE:librdp_viewer_common>"
        )
        add_dependencies(test_workspace_launch_smoke
            librdp-workspace
            librdp_server_common
            librdp_viewer_common
        )
        librdp_configure_test_executable(test_workspace_launch_smoke)
    endif()

    if(TARGET librdp-admin AND
       LIBRDP_CURL_FOUND AND
       LIBRDP_LIBXML2_FOUND)
        add_executable(test_admin_cli_smoke
            tests/test_admin_cli_smoke.c
        )
        add_dependencies(test_admin_cli_smoke librdp-admin)
        librdp_configure_test_executable(test_admin_cli_smoke)
    endif()

    if(TARGET librdp-admin AND
       TARGET librdp-workspace AND
       LIBRDP_CURL_FOUND AND
       LIBRDP_LIBXML2_FOUND)
        add_executable(test_enterprise_cli_failures
            tests/test_enterprise_cli_failures.c
        )
        add_dependencies(test_enterprise_cli_failures
            librdp-admin
            librdp-workspace
        )
        librdp_configure_test_executable(test_enterprise_cli_failures)
    endif()

    add_executable(test_abi_probe tests/abi_probe.c)
    target_include_directories(test_abi_probe PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    librdp_apply_warning_options(test_abi_probe)
    librdp_apply_sanitizer_compile_options(test_abi_probe)
    librdp_apply_sanitizer_link_options(test_abi_probe)

    add_dependencies(librdp_tests
        test_common
        test_core
        test_protocol
        test_transport
        test_server
        test_interop_smoke
        test_optional_backend_probe
        test_viewer_common
        test_admin_workspace
        test_server_host
        test_server_host_drive
        test_server_client_smoke
        test_pnp_virtual_smoke
        test_audio_virtual_smoke
        test_abi_probe
    )
    if(TARGET test_printer_cups_smoke)
        add_dependencies(librdp_tests test_printer_cups_smoke)
    endif()
    if(TARGET test_smartcard_pcsc_smoke)
        add_dependencies(librdp_tests test_smartcard_pcsc_smoke)
    endif()
    if(TARGET test_usb_virtual_smoke)
        add_dependencies(librdp_tests test_usb_virtual_smoke)
    endif()
    if(TARGET test_workspace_launch_smoke)
        add_dependencies(librdp_tests test_workspace_launch_smoke)
    endif()
    if(TARGET test_admin_cli_smoke)
        add_dependencies(librdp_tests test_admin_cli_smoke)
    endif()
    if(TARGET test_enterprise_cli_failures)
        add_dependencies(librdp_tests test_enterprise_cli_failures)
    endif()
    foreach(LIBRDP_NATIVE_TEST_TARGET IN ITEMS
        test_x11_viewer_render
        test_x11_viewer_presentation_smoke
        test_viewer_pointer_server
        test_x11_viewer_audio
        test_x11_pipewire_live_smoke
        test_x11_viewer_camera
        test_x11_camera_live_smoke
        test_x11_viewer_keyboard
        test_x11_viewer_clipboard
        test_x11_viewer_display
        test_x11_viewer_backends
        test_x11_viewer_cli
        test_cocoa_media
        test_cocoa_viewer_render
        test_cocoa_server_cli
        test_cocoa_server_input
        test_cocoa_server_capture
        test_cocoa_server_permission
        test_cocoa_server_clipboard
    )
        if(TARGET ${LIBRDP_NATIVE_TEST_TARGET})
            add_dependencies(librdp_tests ${LIBRDP_NATIVE_TEST_TARGET})
        endif()
    endforeach()

    add_test(NAME common COMMAND test_common)
    add_test(NAME core COMMAND test_core)
    add_test(NAME core_settings_session_error_metrics COMMAND test_core settings)
    add_test(NAME core_connect_timeout COMMAND test_core timeouts)
    add_test(NAME core_resolution_failure COMMAND test_core resolution)
    add_test(NAME core_activation_timeout COMMAND test_core activation-timeout)
    add_test(NAME core_idle_transport_eof COMMAND test_core idle-eof)
    add_test(NAME smoke_client_limits COMMAND test_core limits-smoke)
    set_tests_properties(smoke_client_limits PROPERTIES
        ENVIRONMENT "LIBRDP_TRACE_CLIENT=1;LIBRDP_TRACE_TRANSPORT=1;LIBRDP_TRACE_PROTOCOL=1;LIBRDP_TRACE_LEVEL=trace;LIBRDP_TRACE_HEX_BYTES=16"
        TIMEOUT 60
    )
    add_test(NAME smoke_client_allocation_failures
        COMMAND test_core allocation-fault-smoke)
    set_tests_properties(smoke_client_allocation_failures PROPERTIES
        ENVIRONMENT "LIBRDP_TRACE_CLIENT=1;LIBRDP_TRACE_TRANSPORT=1;LIBRDP_TRACE_PROTOCOL=1;LIBRDP_TRACE_LEVEL=trace;LIBRDP_TRACE_HEX_BYTES=0"
        TIMEOUT 30
    )
    add_test(NAME smoke_client_worker_stalls
        COMMAND test_core worker-stall-smoke)
    set_tests_properties(smoke_client_worker_stalls PROPERTIES
        ENVIRONMENT "LIBRDP_TRACE_CLIENT=1;LIBRDP_TRACE_TRANSPORT=1;LIBRDP_TRACE_PROTOCOL=1;LIBRDP_TRACE_LEVEL=trace;LIBRDP_TRACE_HEX_BYTES=0"
        TIMEOUT 30
    )
    add_test(NAME smoke_trace_sensitive_payloads
        COMMAND test_core trace-privacy-smoke)
    set_tests_properties(smoke_trace_sensitive_payloads PROPERTIES
        TIMEOUT 30
    )
    add_test(NAME smoke_trace_hexdump_bounds
        COMMAND test_core trace-bounds-smoke)
    set_tests_properties(smoke_trace_hexdump_bounds PROPERTIES
        TIMEOUT 30
    )
    add_test(NAME smoke_client_error_boundaries
        COMMAND test_core error-boundaries-smoke)
    set_tests_properties(smoke_client_error_boundaries PROPERTIES
        TIMEOUT 90
    )
    add_test(NAME core_features COMMAND test_core features)
    add_test(NAME core_channels COMMAND test_core channels)
    add_test(NAME smoke_webauthn_mock
        COMMAND test_core webauthn-mock-smoke)
    set_tests_properties(smoke_webauthn_mock PROPERTIES
        ENVIRONMENT "LIBRDP_TRACE_CLIENT=1;LIBRDP_TRACE_PROTOCOL=1;LIBRDP_TRACE_LEVEL=trace;LIBRDP_TRACE_HEX_BYTES=96"
        TIMEOUT 30
    )
    add_test(NAME smoke_multitransport_udp
        COMMAND test_core multitransport-smoke)
    set_tests_properties(smoke_multitransport_udp PROPERTIES
        ENVIRONMENT "LIBRDP_TRACE_CLIENT=1;LIBRDP_TRACE_TRANSPORT=1;LIBRDP_TRACE_PROTOCOL=1;LIBRDP_TRACE_LEVEL=trace;LIBRDP_TRACE_HEX_BYTES=96"
        TIMEOUT 30
    )
    add_test(NAME core_storage_devices COMMAND test_core storage)
    add_test(NAME core_graphics COMMAND test_core graphics)
    add_test(NAME smoke_gdi_orders COMMAND test_core gdi-orders-smoke)
    add_test(NAME smoke_gdi_cache_lifecycle COMMAND test_core gdi-cache-smoke)
    set_tests_properties(smoke_gdi_cache_lifecycle PROPERTIES
        ENVIRONMENT "LIBRDP_TRACE_CLIENT=1;LIBRDP_TRACE_LEVEL=debug"
        TIMEOUT 60
    )
    add_test(NAME smoke_gdi_cache_eviction COMMAND test_core gdi-cache-eviction)
    set_tests_properties(smoke_gdi_cache_eviction PROPERTIES TIMEOUT 60)
    add_test(NAME smoke_pointer_cache_lifecycle
        COMMAND test_core pointer-cache-smoke)
    set_tests_properties(smoke_pointer_cache_lifecycle PROPERTIES
        ENVIRONMENT "LIBRDP_TRACE_CLIENT=1;LIBRDP_TRACE_LEVEL=debug"
        TIMEOUT 60
    )
    add_test(NAME smoke_composition_cr2
        COMMAND test_core composition-cr2-smoke)
    set_tests_properties(smoke_composition_cr2 PROPERTIES
        ENVIRONMENT "LIBRDP_TRACE_CLIENT=1;LIBRDP_TRACE_LEVEL=debug"
        TIMEOUT 60
    )
    add_test(NAME smoke_rail_runtime
        COMMAND test_core rail-runtime-smoke)
    set_tests_properties(smoke_rail_runtime PROPERTIES
        ENVIRONMENT "LIBRDP_TEST_TRACE_OUTPUT=1"
        TIMEOUT 60
    )
    add_test(NAME smoke_video_geometry
        COMMAND test_core video-geometry-smoke)
    set_tests_properties(smoke_video_geometry PROPERTIES
        ENVIRONMENT "LIBRDP_TEST_TRACE_OUTPUT=1"
        TIMEOUT 60
    )
    add_test(NAME smoke_display_control_resize
        COMMAND test_core display-resize-smoke)
    set_tests_properties(smoke_display_control_resize PROPERTIES
        ENVIRONMENT "LIBRDP_TRACE_CLIENT=1;LIBRDP_TRACE_PROTOCOL=1;LIBRDP_TRACE_LEVEL=debug;LIBRDP_TRACE_HEX_BYTES=0"
        TIMEOUT 60
    )
    add_test(NAME smoke_display_control_layout
        COMMAND test_core display-layout-smoke)
    set_tests_properties(smoke_display_control_layout PROPERTIES
        ENVIRONMENT "LIBRDP_TRACE_CLIENT=1;LIBRDP_TRACE_PROTOCOL=1;LIBRDP_TRACE_LEVEL=debug;LIBRDP_TRACE_HEX_BYTES=0"
        TIMEOUT 60
    )
    if(LIBRDP_CAIRO_FOUND)
        add_test(NAME smoke_gdiplus_cairo
            COMMAND test_core gdiplus-native-smoke)
        set_tests_properties(smoke_gdiplus_cairo PROPERTIES
            ENVIRONMENT "LIBRDP_TEST_GDIPLUS_BACKEND=cairo"
            TIMEOUT 60
        )
    endif()
    if(LIBRDP_QUARTZ_FOUND)
        add_test(NAME smoke_gdiplus_quartz
            COMMAND test_core gdiplus-native-smoke)
        set_tests_properties(smoke_gdiplus_quartz PROPERTIES
            ENVIRONMENT "LIBRDP_TEST_GDIPLUS_BACKEND=quartz"
            TIMEOUT 60
        )
    endif()
    add_test(NAME core_reactivation COMMAND test_core reactivation)
    add_test(NAME core_licensing COMMAND test_core licensing)
    add_test(NAME core_workspace_admin COMMAND test_core enterprise)
    add_test(NAME protocol COMMAND test_protocol)
    add_test(NAME protocol_core COMMAND test_protocol core)
    add_test(NAME protocol_channels COMMAND test_protocol channels)
    add_test(NAME protocol_updates COMMAND test_protocol updates)
    add_test(NAME protocol_codecs COMMAND test_protocol codecs)
    add_test(NAME protocol_activation COMMAND test_protocol activation)
    add_test(NAME protocol_security COMMAND test_protocol security)
    add_test(NAME protocol_interaction COMMAND test_protocol interaction)
    add_test(NAME protocol_graphics COMMAND test_protocol graphics)
    add_test(NAME protocol_graphics_pipeline COMMAND test_protocol graphics-pipeline)
    add_test(NAME protocol_clipboard COMMAND test_protocol clipboard)
    add_test(NAME protocol_authentication COMMAND test_protocol authentication)
    add_test(NAME protocol_devices COMMAND test_protocol devices)
    add_test(NAME protocol_transport COMMAND test_protocol transport)
    add_test(NAME transport COMMAND test_transport)
    add_test(NAME transport_timeout_boundaries COMMAND test_transport timeouts)
    add_test(NAME transport_tls_sigpipe COMMAND test_transport tls-sigpipe)
    add_test(NAME server COMMAND test_server)
    add_test(NAME server_config COMMAND test_server config)
    add_test(NAME server_feature_status COMMAND test_server features)
    add_test(NAME server_security COMMAND test_server security)
    add_test(NAME server_lifecycle COMMAND test_server lifecycle)
    add_test(NAME server_protocol_order COMMAND test_server protocol-order)
    add_test(NAME server_desktop_limits COMMAND test_server desktop-limits)
    add_test(NAME server_channels COMMAND test_server channels)
    add_test(NAME server_drive_metadata COMMAND test_server drive-metadata)
    add_test(NAME server_graphics COMMAND test_server graphics)
    add_test(NAME server_runtime COMMAND test_server runtime)
    add_test(NAME smoke_server_standard COMMAND test_server smoke-standard)
    add_test(NAME smoke_server_tls COMMAND test_server smoke-tls)
    add_test(NAME smoke_server_nla COMMAND test_server smoke-nla)
    add_test(NAME smoke_gateway COMMAND test_transport smoke-gateway)
    add_test(NAME smoke_workspace COMMAND test_core smoke-workspace)
    add_test(NAME smoke_admin COMMAND test_core smoke-admin)
    add_test(NAME interop_smoke COMMAND test_interop_smoke)
    add_test(NAME viewer_common COMMAND test_viewer_common)
    add_test(NAME admin_workspace COMMAND test_admin_workspace)
    add_test(NAME server_host COMMAND test_server_host)
    add_test(NAME server_host_drive COMMAND test_server_host_drive)
    add_test(NAME server_client_smoke_standard
        COMMAND test_server_client_smoke standard)
    add_test(NAME server_client_smoke_standard_dns
        COMMAND test_server_client_smoke standard-dns)
    add_test(NAME server_client_smoke_standard_ipv6
        COMMAND test_server_client_smoke standard-ipv6)
    add_test(NAME server_client_smoke_tls
        COMMAND test_server_client_smoke tls)
    add_test(NAME server_client_smoke_nla
             COMMAND test_server_client_smoke nla)
    add_test(NAME server_client_smoke_auth_redirection
             COMMAND test_server_client_smoke auth-redirection)
    add_test(NAME server_client_smoke_input_touch
             COMMAND test_server_client_input_smoke touch)
    add_test(NAME server_client_smoke_input_touch_fallback
             COMMAND test_server_client_input_smoke touch-fallback)
    add_test(NAME server_client_smoke_input_pen
             COMMAND test_server_client_input_smoke pen)
    add_test(NAME server_client_smoke_input_core
             COMMAND test_server_client_input_smoke core)
    add_test(NAME server_client_smoke_input_core_fallback
             COMMAND test_server_client_input_smoke core-fallback)
    add_test(NAME server_client_smoke_serial_port
             COMMAND test_server_client_port_smoke serial)
    add_test(NAME server_client_smoke_parallel_port
             COMMAND test_server_client_port_smoke parallel)
    add_test(NAME pnp_virtual_smoke
             COMMAND test_pnp_virtual_smoke)
    set_tests_properties(pnp_virtual_smoke PROPERTIES
        TIMEOUT 15
    )
    add_test(NAME audio_virtual_smoke
             COMMAND test_audio_virtual_smoke)
    set_tests_properties(audio_virtual_smoke PROPERTIES
        TIMEOUT 15
    )
    add_test(NAME video_virtual_smoke
             COMMAND test_video_virtual_smoke)
    set_tests_properties(video_virtual_smoke PROPERTIES
        TIMEOUT 15
    )
    if(TARGET test_printer_cups_smoke)
        add_test(NAME printer_cups_smoke
                 COMMAND test_printer_cups_smoke)
        set_tests_properties(printer_cups_smoke PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 15
        )
    endif()
    if(TARGET test_smartcard_pcsc_smoke)
        add_test(NAME smartcard_pcsc_smoke
                 COMMAND test_smartcard_pcsc_smoke)
        set_tests_properties(smartcard_pcsc_smoke PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 25
        )
    endif()
    if(TARGET test_usb_virtual_smoke)
        add_test(NAME usb_virtual_smoke
                 COMMAND test_usb_virtual_smoke)
        set_tests_properties(usb_virtual_smoke PROPERTIES
            TIMEOUT 15
        )
        add_test(NAME smoke_client_usb_worker_stall
                 COMMAND test_usb_virtual_smoke worker-stall)
        set_tests_properties(smoke_client_usb_worker_stall PROPERTIES
            ENVIRONMENT "LIBRDP_TRACE_CLIENT=1;LIBRDP_TRACE_TRANSPORT=1;LIBRDP_TRACE_PROTOCOL=1;LIBRDP_TRACE_LEVEL=trace;LIBRDP_TRACE_HEX_BYTES=0"
            TIMEOUT 15
        )
    endif()
    add_test(NAME server_client_smoke_clipboard_text
             COMMAND test_server_client_smoke clipboard-text)
    add_test(NAME server_client_smoke_clipboard_html
             COMMAND test_server_client_smoke clipboard-html)
    add_test(NAME server_client_smoke_clipboard_png
             COMMAND test_server_client_smoke clipboard-png)
    add_test(NAME server_client_smoke_clipboard_files
             COMMAND test_server_client_smoke clipboard-files)
    add_test(NAME server_client_smoke_drive_read_only
             COMMAND test_server_client_smoke drive-read-only)
    add_test(NAME server_client_smoke_drive_writable
             COMMAND test_server_client_smoke drive-writable)
    add_test(NAME server_client_smoke_drive_information
             COMMAND test_server_client_smoke drive-information)
    add_test(NAME server_client_smoke_drive_enumeration
             COMMAND test_server_client_smoke drive-enumeration)
    add_test(NAME server_client_smoke_drive_locking
             COMMAND test_server_client_smoke drive-locking)
    add_test(NAME server_client_smoke_drive_notify
             COMMAND test_server_client_smoke drive-notify)
    add_test(NAME server_client_smoke_drive_confinement
             COMMAND test_server_client_smoke drive-confinement)
    add_test(NAME server_client_smoke_drive_device_node
             COMMAND test_server_client_smoke drive-device-node)
    add_test(NAME server_client_smoke_drive_limits
             COMMAND test_server_client_smoke drive-limits)
    if(LIBRDP_ATTR_FOUND AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_test(NAME server_client_smoke_drive_metadata
                 COMMAND test_server_client_smoke drive-metadata)
    endif()
    if(TARGET test_workspace_launch_smoke)
        add_test(NAME workspace_desktop_launch_smoke
            COMMAND test_workspace_launch_smoke
                desktop
                $<TARGET_FILE:librdp-workspace>
                $<TARGET_FILE:test_workspace_launch_smoke>
        )
        add_test(NAME workspace_remoteapp_launch_smoke
            COMMAND test_workspace_launch_smoke
                remoteapp
                $<TARGET_FILE:librdp-workspace>
                $<TARGET_FILE:test_workspace_launch_smoke>
        )
        set_tests_properties(
            workspace_desktop_launch_smoke
            workspace_remoteapp_launch_smoke
            PROPERTIES TIMEOUT 30
        )
    endif()
    if(TARGET test_admin_cli_smoke)
        add_test(NAME admin_inventory_cli_smoke
            COMMAND test_admin_cli_smoke
                inventory
                $<TARGET_FILE:librdp-admin>
        )
        add_test(NAME admin_actions_cli_smoke
            COMMAND test_admin_cli_smoke
                actions
                $<TARGET_FILE:librdp-admin>
        )
        set_tests_properties(
            admin_inventory_cli_smoke
            admin_actions_cli_smoke
            PROPERTIES TIMEOUT 30
        )
    endif()
    if(TARGET test_enterprise_cli_failures)
        foreach(LIBRDP_ENTERPRISE_FAILURE_CASE IN ITEMS
                workspace-tls
                admin-tls
                workspace-auth
                admin-auth
                workspace-malformed
                admin-malformed
                workspace-empty
                workspace-duplicate
                admin-action-timeout)
            string(REPLACE "-" "_" LIBRDP_ENTERPRISE_FAILURE_TEST
                "${LIBRDP_ENTERPRISE_FAILURE_CASE}")
            add_test(
                NAME enterprise_${LIBRDP_ENTERPRISE_FAILURE_TEST}_smoke
                COMMAND test_enterprise_cli_failures
                    ${LIBRDP_ENTERPRISE_FAILURE_CASE}
                    $<TARGET_FILE:librdp-workspace>
                    $<TARGET_FILE:librdp-admin>
            )
            set_tests_properties(
                enterprise_${LIBRDP_ENTERPRISE_FAILURE_TEST}_smoke
                PROPERTIES TIMEOUT 30
            )
        endforeach()
    endif()
    add_test(NAME server_client_smoke_nla_invalid
             COMMAND test_server_client_smoke nla-invalid)
    add_test(NAME server_client_smoke_nla_unknown_user
             COMMAND test_server_client_smoke nla-unknown-user)
    add_test(NAME server_client_smoke_nla_wrong_domain
             COMMAND test_server_client_smoke nla-wrong-domain)
    add_test(NAME server_client_smoke_nla_expired
             COMMAND test_server_client_smoke nla-expired)
    add_test(NAME server_client_smoke_nla_locked
             COMMAND test_server_client_smoke nla-locked)
    add_test(NAME server_client_smoke_nla_no_domain
             COMMAND test_server_client_smoke nla-no-domain)
    add_test(NAME server_client_smoke_nla_empty_domain
             COMMAND test_server_client_smoke nla-empty-domain)
    add_test(NAME server_client_smoke_nla_upn
             COMMAND test_server_client_smoke nla-upn)
    add_test(NAME server_client_smoke_nla_utf8
             COMMAND test_server_client_smoke nla-utf8)
    add_test(NAME server_client_smoke_credssp_timeout
             COMMAND test_server_client_smoke timeout-credssp)
    add_test(NAME server_client_smoke_standard_integrity
             COMMAND test_server_client_smoke standard-integrity)
    add_test(NAME server_client_smoke_fastpath_bitmap
             COMMAND test_server_client_smoke fastpath-bitmap)
    add_test(NAME server_client_smoke_fastpath_nscodec
             COMMAND test_server_client_smoke fastpath-nscodec)
    add_test(NAME server_client_smoke_fastpath_rfx
             COMMAND test_server_client_smoke fastpath-rfx)
    add_test(NAME server_client_smoke_graphics_planar
             COMMAND test_server_client_smoke graphics-planar)
    add_test(NAME server_client_smoke_graphics_progressive
             COMMAND test_server_client_smoke graphics-progressive)
    add_test(NAME server_client_smoke_graphics_lifecycle
             COMMAND test_server_client_smoke graphics-lifecycle)
    add_test(NAME server_client_smoke_graphics_multi_surface
             COMMAND test_server_client_smoke graphics-multi-surface)
    add_test(NAME server_client_smoke_graphics_clearcodec
             COMMAND test_server_client_smoke graphics-clearcodec)
    add_test(NAME server_client_smoke_graphics_backpressure
             COMMAND test_server_client_smoke graphics-backpressure)
    add_test(NAME server_client_smoke_graphics_motion
             COMMAND test_server_client_smoke graphics-motion)
    if(TARGET test_x11_viewer_presentation_smoke)
        add_test(NAME x11_viewer_presentation_smoke
                 COMMAND test_x11_viewer_presentation_smoke)
        set_tests_properties(
            x11_viewer_presentation_smoke
            PROPERTIES
                RUN_SERIAL TRUE
                TIMEOUT 360
        )
    endif()
    if(LIBRDP_FFMPEG_AVC_FOUND OR
       LIBRDP_OPENH264_AVC_FOUND)
        add_test(NAME server_client_smoke_graphics_avc
                 COMMAND test_server_client_smoke graphics-avc)
    endif()
    add_test(NAME server_client_smoke_security_downgrade
             COMMAND test_server_client_smoke security-downgrade)
    add_test(NAME server_client_smoke_tls_untrusted
             COMMAND test_server_client_smoke tls-untrusted)
    add_test(NAME server_client_smoke_tls_hostname
             COMMAND test_server_client_smoke tls-hostname)
    add_test(NAME server_client_smoke_tls_wrong_pin
             COMMAND test_server_client_smoke tls-wrong-pin)
    add_test(NAME server_client_smoke_tls_handshake
             COMMAND test_server_client_smoke tls-handshake)
    add_test(NAME server_client_smoke_redirection_standard
             COMMAND test_server_client_smoke redirection-standard)
    add_test(NAME server_client_smoke_redirection_tls
             COMMAND test_server_client_smoke redirection-tls)
    add_test(NAME server_client_smoke_redirection_loop
             COMMAND test_server_client_smoke redirection-loop)
    add_test(NAME server_client_smoke_output_control
             COMMAND test_server_client_smoke output-control)
    add_test(NAME server_client_smoke_cancel_connecting
             COMMAND test_server_client_smoke cancel-connecting)
    add_test(NAME server_client_smoke_cancel_negotiating
             COMMAND test_server_client_smoke cancel-negotiating)
    add_test(NAME server_client_smoke_cancel_tls
             COMMAND test_server_client_smoke cancel-tls)
    add_test(NAME server_client_smoke_cancel_authenticating
             COMMAND test_server_client_smoke cancel-authenticating)
    add_test(NAME server_client_smoke_cancel_activating
             COMMAND test_server_client_smoke cancel-activating)
    add_test(NAME server_client_smoke_lifecycle_stress
             COMMAND test_server_client_smoke lifecycle-stress)
    if(LIBRDP_CURL_FOUND)
        add_test(NAME server_client_smoke_gateway_http_connect
                 COMMAND test_server_client_smoke gateway-http-connect)
        add_test(NAME server_client_smoke_gateway_session_credentials
                 COMMAND test_server_client_smoke gateway-session-credentials)
        add_test(NAME server_client_smoke_gateway_no_session_credentials
                 COMMAND test_server_client_smoke gateway-no-session-credentials)
        add_test(NAME server_client_smoke_gateway_auth_failure
                 COMMAND test_server_client_smoke gateway-auth-failure)
        add_test(NAME server_client_smoke_gateway_timeout
                 COMMAND test_server_client_smoke gateway-timeout)
        add_test(NAME server_client_smoke_gateway_malformed
                 COMMAND test_server_client_smoke gateway-malformed)
        add_test(NAME server_client_smoke_gateway_refused
                 COMMAND test_server_client_smoke gateway-refused)
        add_test(NAME server_client_smoke_gateway_rdg
                 COMMAND test_server_client_smoke gateway-rdg)
        add_test(NAME server_client_smoke_gateway_rdg_drop_out
                 COMMAND test_server_client_smoke gateway-rdg-drop-out)
        add_test(NAME server_client_smoke_gateway_rdg_drop_in
                 COMMAND test_server_client_smoke gateway-rdg-drop-in)
        add_test(NAME server_client_smoke_gateway_rdg_untrusted
                 COMMAND test_server_client_smoke gateway-rdg-untrusted)
    endif()
    set_tests_properties(
        common
        transport
        viewer_common
        admin_workspace
        server_host
        server_host_drive
        PROPERTIES TIMEOUT 30
    )
    set_tests_properties(
        server_client_smoke_standard
        server_client_smoke_standard_dns
        server_client_smoke_standard_ipv6
        server_client_smoke_tls
        server_client_smoke_nla
        server_client_smoke_auth_redirection
        server_client_smoke_input_touch
        server_client_smoke_input_touch_fallback
        server_client_smoke_input_pen
        server_client_smoke_input_core
        server_client_smoke_input_core_fallback
        server_client_smoke_serial_port
        server_client_smoke_parallel_port
        server_client_smoke_clipboard_text
        server_client_smoke_clipboard_html
        server_client_smoke_clipboard_png
        server_client_smoke_clipboard_files
        server_client_smoke_drive_read_only
        server_client_smoke_drive_writable
        server_client_smoke_drive_notify
        server_client_smoke_drive_confinement
        server_client_smoke_drive_device_node
        server_client_smoke_drive_limits
        server_client_smoke_nla_invalid
        server_client_smoke_nla_expired
        server_client_smoke_nla_locked
        server_client_smoke_nla_no_domain
        server_client_smoke_nla_empty_domain
        server_client_smoke_nla_upn
        server_client_smoke_nla_utf8
        server_client_smoke_credssp_timeout
        server_client_smoke_standard_integrity
        server_client_smoke_fastpath_bitmap
        server_client_smoke_fastpath_nscodec
        server_client_smoke_fastpath_rfx
        server_client_smoke_graphics_planar
        server_client_smoke_graphics_progressive
        server_client_smoke_graphics_lifecycle
        server_client_smoke_graphics_multi_surface
        server_client_smoke_graphics_clearcodec
        server_client_smoke_graphics_backpressure
        server_client_smoke_graphics_motion
        server_client_smoke_security_downgrade
        server_client_smoke_tls_untrusted
        server_client_smoke_tls_hostname
        server_client_smoke_tls_wrong_pin
        server_client_smoke_tls_handshake
        server_client_smoke_redirection_standard
        server_client_smoke_redirection_tls
        server_client_smoke_redirection_loop
        server_client_smoke_output_control
        server_client_smoke_cancel_connecting
        server_client_smoke_cancel_negotiating
        server_client_smoke_cancel_tls
        server_client_smoke_cancel_authenticating
        server_client_smoke_cancel_activating
        PROPERTIES TIMEOUT 60
    )
    if(TEST server_client_smoke_drive_metadata)
        set_tests_properties(
            server_client_smoke_drive_metadata
            PROPERTIES TIMEOUT 60
        )
    endif()
    set_tests_properties(
        server_client_smoke_lifecycle_stress
        PROPERTIES TIMEOUT 180
    )
    if(TEST server_client_smoke_gateway_http_connect)
        set_tests_properties(
            server_client_smoke_gateway_http_connect
            server_client_smoke_gateway_session_credentials
            server_client_smoke_gateway_no_session_credentials
            server_client_smoke_gateway_auth_failure
            server_client_smoke_gateway_timeout
            server_client_smoke_gateway_malformed
            server_client_smoke_gateway_refused
            server_client_smoke_gateway_rdg
            server_client_smoke_gateway_rdg_drop_out
            server_client_smoke_gateway_rdg_drop_in
            server_client_smoke_gateway_rdg_untrusted
            PROPERTIES TIMEOUT 60
        )
    endif()
    set_tests_properties(
        server
        server_security
        server_runtime
        smoke_server_standard
        smoke_server_tls
        smoke_server_nla
        PROPERTIES TIMEOUT 60
    )
    set_tests_properties(
        server_config
        server_feature_status
        server_lifecycle
        server_protocol_order
        server_desktop_limits
        server_channels
        server_drive_metadata
        server_graphics
        PROPERTIES TIMEOUT 30
    )
    set_tests_properties(
        core
        core_settings_session_error_metrics
        core_connect_timeout
        core_resolution_failure
        core_activation_timeout
        core_idle_transport_eof
        core_channels
        core_storage_devices
        core_graphics
        core_reactivation
        core_licensing
        core_workspace_admin
        PROPERTIES TIMEOUT 60
    )
    set_tests_properties(core_features PROPERTIES TIMEOUT 30)
    set_tests_properties(transport_timeout_boundaries PROPERTIES TIMEOUT 30)
    set_tests_properties(
        protocol
        protocol_codecs
        protocol_channels
        protocol_security
        protocol_graphics
        protocol_graphics_pipeline
        PROPERTIES TIMEOUT 90
    )
    set_tests_properties(
        protocol_core
        protocol_updates
        protocol_activation
        protocol_interaction
        protocol_clipboard
        protocol_authentication
        protocol_devices
        protocol_transport
        PROPERTIES TIMEOUT 30
    )
    set_tests_properties(
        smoke_gateway
        smoke_workspace
        smoke_admin
        PROPERTIES TIMEOUT 30 SKIP_RETURN_CODE 77
    )
    set_tests_properties(interop_smoke PROPERTIES TIMEOUT 180 SKIP_RETURN_CODE 77)
    add_test(NAME core_optional_backends_off
        COMMAND ${CMAKE_COMMAND}
            "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
            "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
            "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
            ${LIBRDP_NESTED_CONFIGURE_ARGS}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/core_optional_backends_off.cmake)
    set_tests_properties(core_optional_backends_off PROPERTIES TIMEOUT 300)
    add_test(NAME optional_backend_matrix
        COMMAND ${CMAKE_COMMAND}
            "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
            "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
            "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
            ${LIBRDP_NESTED_CONFIGURE_ARGS}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/optional_backend_matrix.cmake)
    set_tests_properties(optional_backend_matrix PROPERTIES TIMEOUT 300)
    add_test(NAME shared_symbol_visibility
        COMMAND ${CMAKE_COMMAND}
            "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
            "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
            "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
            "-DLIBRDP_SHARED_LIBRARY_SUFFIX=${CMAKE_SHARED_LIBRARY_SUFFIX}"
            "-DLIBRDP_ABI_VERSION=${LIBRDP_ABI_VERSION}"
            ${LIBRDP_NESTED_CONFIGURE_ARGS}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/shared_symbol_visibility.cmake)
    set_tests_properties(shared_symbol_visibility PROPERTIES TIMEOUT 300)
    add_test(NAME library_type_selection
        COMMAND ${CMAKE_COMMAND}
            "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
            "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
            "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
            "-DLIBRDP_SHARED_LIBRARY_SUFFIX=${CMAKE_SHARED_LIBRARY_SUFFIX}"
            "-DLIBRDP_STATIC_LIBRARY_SUFFIX=${CMAKE_STATIC_LIBRARY_SUFFIX}"
            ${LIBRDP_NESTED_CONFIGURE_ARGS}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/library_type_selection.cmake)
    set_tests_properties(library_type_selection PROPERTIES TIMEOUT 300)
    if(Python3_Interpreter_FOUND)
        add_test(NAME abi_baseline
            COMMAND ${CMAKE_COMMAND}
                "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
                "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
                "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
                "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
                "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
                "-DLIBRDP_SHARED_LIBRARY_SUFFIX=${CMAKE_SHARED_LIBRARY_SUFFIX}"
                "-DLIBRDP_PYTHON_EXECUTABLE=${Python3_EXECUTABLE}"
                ${LIBRDP_NESTED_CONFIGURE_ARGS}
                -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/abi_baseline.cmake)
        set_tests_properties(abi_baseline PROPERTIES TIMEOUT 300)
    endif()
    add_test(NAME installed_public_api_consumer
        COMMAND ${CMAKE_COMMAND}
            "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
            "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
            "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
            ${LIBRDP_NESTED_CONFIGURE_ARGS}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/install_consumer.cmake)
    set_tests_properties(installed_public_api_consumer PROPERTIES TIMEOUT 300)
    if(LIBRDP_SANITIZER_ADDRESS_LINKS AND LIBRDP_SANITIZER_UNDEFINED_LINKS)
        add_test(NAME sanitizer_core
            COMMAND ${CMAKE_COMMAND}
                "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
                "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
                "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
                "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
                "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
                ${LIBRDP_NESTED_CONFIGURE_ARGS}
                -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/sanitizer_core.cmake)
        set_tests_properties(sanitizer_core PROPERTIES TIMEOUT 300)
    endif()
    if(Python3_Interpreter_FOUND)
        add_test(NAME license_headers
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-license-headers.py ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(license_headers PROPERTIES
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            TIMEOUT 60
        )
        add_test(NAME license_archive_fallback
            COMMAND ${CMAKE_COMMAND}
                "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
                "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                "-DLIBRDP_PYTHON_EXECUTABLE=${Python3_EXECUTABLE}"
                -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/license_archive_fallback.cmake)
        set_tests_properties(license_archive_fallback PROPERTIES TIMEOUT 60)
        add_test(NAME public_api_docs
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-public-api-docs.py)
        add_test(NAME source_comments
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-source-comments.py)
        add_test(NAME source_size_advisory
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-source-size.py)
        add_test(NAME internal_header_comments
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-internal-header-comments.py)
        add_test(NAME test_fuzz_comments
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-test-fuzz-comments.py)
        add_test(NAME fuzz_corpus
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-fuzz-corpus.py)
        add_test(NAME feature_status_reasons
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-feature-status-reasons.py)
        add_test(NAME application_public_includes
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-app-public-includes.py)
        add_test(NAME examples_docs
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-examples.py)
        add_test(NAME docs
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-docs.py)
        set_tests_properties(
            public_api_docs
            source_comments
            source_size_advisory
            internal_header_comments
            test_fuzz_comments
            fuzz_corpus
            feature_status_reasons
            application_public_includes
            examples_docs
            docs
            PROPERTIES TIMEOUT 60
        )
        add_test(NAME sbom_generation
            COMMAND ${CMAKE_COMMAND}
                "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
                "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                "-DLIBRDP_PYTHON_EXECUTABLE=${Python3_EXECUTABLE}"
                "-DLIBRDP_TEST_BUILD_ADMIN=${LIBRDP_BUILD_ADMIN}"
                "-DLIBRDP_TEST_BUILD_SERVER=${LIBRDP_BUILD_SERVER}"
                "-DLIBRDP_TEST_BUILD_VIEWER=${LIBRDP_BUILD_VIEWER}"
                "-DLIBRDP_TEST_BUILD_WORKSPACE=${LIBRDP_BUILD_WORKSPACE}"
                "-DLIBRDP_TEST_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}"
                -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/sbom_generation.cmake)
        set_tests_properties(sbom_generation PROPERTIES TIMEOUT 120)
        if(DOXYGEN_FOUND)
            add_test(NAME doxygen_public_headers
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-doxygen.py)
            set_tests_properties(doxygen_public_headers PROPERTIES TIMEOUT 180)
        endif()
    endif()
endif()
